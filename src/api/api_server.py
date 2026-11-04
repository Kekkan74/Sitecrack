"""
Backend de Datos RESTful y Servidor de la Aplicación Gráfica (FastAPI) - api_server.py

Diseño SOLID:
- SRP: Gestiona el enrutamiento HTTP REST, validación de esquemas y entrega de la interfaz gráfica.
- DIP: Utiliza Inyección de Dependencias (`Depends(get_repository)`) desacoplando los
  controladores FastAPI del motor SQLite subyacente.

Ejecución:
    uvicorn src.api.api_server:app --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import List, Literal, Optional
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from src.api.database import FlowRepositoryProtocol, SQLiteFlowRepository
from src.core.security_analyzer import PassiveSecurityAnalyzer, sanitize_headers
from src.domain.schemas import HttpFlowCreate, HttpFlowRecord, TrafficStats
from src.ui.api_client import DemoTelemetryClient

PROJECT_ROOT = Path(__file__).resolve().parents[2]
WEB_UI_DIR = PROJECT_ROOT / "src" / "ui" / "web"

DEFAULT_DB_PATH = Path(
    os.getenv(
        "SITECRACK_DB_PATH",
        str(PROJECT_ROOT / "data" / "sitecrack_flows.db"),
    )
)


class SimulationRequest(BaseModel):
    """Petición de simulación enviada desde el modal de la aplicación gráfica."""

    url: str = Field(..., min_length=4, max_length=2048)
    method: str = Field(default="GET", max_length=16)
    status_code: int = Field(default=200, ge=100, le=599)
    preset: Literal["hardened", "partial", "vulnerable"] = "hardened"


@lru_cache(maxsize=1)
def get_repository() -> FlowRepositoryProtocol:
    """Proveedor singleton del repositorio SQLite para Inyección de Dependencias."""
    return SQLiteFlowRepository(db_path=DEFAULT_DB_PATH)


app = FastAPI(
    title="Sitecrack Graphical App & Telemetry API",
    description=(
        "Aplicación gráfica y backend RESTful ligero de inspección pasiva de tráfico "
        "HTTP/S para la suite de auditoría web Sitecrack."
    ),
    version="2.0.0",
)

if WEB_UI_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(WEB_UI_DIR)), name="static")


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def serve_graphical_app() -> FileResponse:
    """Entrega la interfaz gráfica principal de Sitecrack."""
    return FileResponse(str(WEB_UI_DIR / "index.html"))


@app.get("/health", tags=["System"])
def health_check() -> dict[str, str]:
    """Verifica disponibilidad operativa del servicio Backend."""
    return {"status": "online", "service": "sitecrack-app", "version": "2.0.0"}


@app.post(
    "/api/v1/flows",
    response_model=HttpFlowRecord,
    status_code=status.HTTP_201_CREATED,
    tags=["Flows"],
)
@app.post(
    "/flows",
    response_model=HttpFlowRecord,
    status_code=status.HTTP_201_CREATED,
    include_in_schema=False,
)
def ingest_flow(
    payload: HttpFlowCreate,
    repo: FlowRepositoryProtocol = Depends(get_repository),
) -> HttpFlowRecord:
    """Recibe y persiste un flujo HTTP/S interceptado desde `proxy_core.py`."""
    return repo.save_flow(payload)


@app.post(
    "/api/v1/demo-seed",
    response_model=List[HttpFlowRecord],
    status_code=status.HTTP_201_CREATED,
    tags=["Flows"],
)
def seed_demo_flows(
    repo: FlowRepositoryProtocol = Depends(get_repository),
) -> List[HttpFlowRecord]:
    """Carga flujos de ejemplo en la base de datos para explorar la app al instante."""
    demo_records = DemoTelemetryClient().fetch_flows(limit=10)
    saved: List[HttpFlowRecord] = []
    for item in reversed(demo_records):
        dto = HttpFlowCreate(**item.model_dump(exclude={"id"}))
        saved.append(repo.save_flow(dto))
    return saved


@app.post(
    "/api/v1/simulate",
    response_model=HttpFlowRecord,
    status_code=status.HTTP_201_CREATED,
    tags=["Flows"],
)
def simulate_custom_flow(
    sim: SimulationRequest,
    repo: FlowRepositoryProtocol = Depends(get_repository),
) -> HttpFlowRecord:
    """Permite crear y auditar una petición de prueba desde la interfaz gráfica."""
    parsed = urlparse(sim.url if "://" in sim.url else f"https://{sim.url}")
    scheme = (parsed.scheme or "https").lower()
    host = parsed.netloc or "ejemplo.local"
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    if sim.preset == "hardened":
        resp_headers = {
            "Content-Type": "application/json",
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=()",
        }
    elif sim.preset == "partial":
        resp_headers = {
            "Content-Type": "application/json",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
        }
    else:
        resp_headers = {
            "Content-Type": "application/json",
            "Server": "Apache/2.4.49 (Unix)",
        }

    analyzer = PassiveSecurityAnalyzer()
    audit = analyzer.evaluate(scheme=scheme, response_headers=resp_headers)

    req_headers = sanitize_headers(
        {
            "Host": host,
            "User-Agent": "Sitecrack-App-Simulator/2.0",
            "Accept": "application/json",
            "Authorization": "Bearer token_simulado_secreto_999",
        }
    )

    flow_dto = HttpFlowCreate(
        method=sim.method.upper(),
        scheme=scheme,
        host=host,
        path=path,
        url=f"{scheme}://{host}{path}",
        status_code=sim.status_code,
        content_type="application/json",
        duration_ms=24.6,
        request_size=64 if sim.method.upper() in ("POST", "PUT") else 0,
        response_size=192,
        request_headers=req_headers,
        response_headers=resp_headers,
        request_preview='{"accion": "prueba_desde_interfaz"}'
        if sim.method.upper() in ("POST", "PUT")
        else "",
        response_preview=f'{{"resultado": "simulado", "codigo": {sim.status_code}, "proteccion": "{sim.preset}"}}',
        security_audit=audit,
    )
    return repo.save_flow(flow_dto)


@app.get(
    "/api/v1/flows",
    response_model=List[HttpFlowRecord],
    tags=["Flows"],
)
@app.get(
    "/flows",
    response_model=List[HttpFlowRecord],
    include_in_schema=False,
)
def list_captured_flows(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    method: Optional[str] = Query(default=None, max_length=16),
    host: Optional[str] = Query(default=None, max_length=255),
    min_status: Optional[int] = Query(default=None, ge=100, le=599),
    repo: FlowRepositoryProtocol = Depends(get_repository),
) -> List[HttpFlowRecord]:
    """Devuelve la lista paginada y filtrada de flujos HTTP/S capturados."""
    return repo.list_flows(
        limit=limit,
        offset=offset,
        method=method,
        host_filter=host,
        min_status=min_status,
    )


@app.get(
    "/api/v1/flows/{flow_id}",
    response_model=HttpFlowRecord,
    tags=["Flows"],
)
def get_flow_detail(
    flow_id: int,
    repo: FlowRepositoryProtocol = Depends(get_repository),
) -> HttpFlowRecord:
    """Obtiene el detalle completo (cabeceras, vista previa y auditoría) de un flujo."""
    record = repo.get_flow_by_id(flow_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Flujo con ID {flow_id} no encontrado.",
        )
    return record


@app.get(
    "/api/v1/stats",
    response_model=TrafficStats,
    tags=["Metrics"],
)
def get_traffic_stats(
    repo: FlowRepositoryProtocol = Depends(get_repository),
) -> TrafficStats:
    """Calcula estadísticas agregadas de tráfico y postura de seguridad."""
    return repo.get_stats()


@app.delete(
    "/api/v1/flows",
    tags=["Flows"],
)
def clear_captured_flows(
    repo: FlowRepositoryProtocol = Depends(get_repository),
) -> dict[str, int]:
    """Limpia el historial de flujos almacenados en la base de datos local."""
    deleted_count = repo.clear_flows()
    return {"deleted": deleted_count}
