"""
Backend de Datos RESTful (FastAPI) - api_server.py

Diseño SOLID:
- SRP: Gestiona exclusivamente el enrutamiento HTTP REST, validación de esquemas y códigos de estado.
- DIP: Utiliza Inyección de Dependencias (`Depends(get_repository)`) desacoplando los
  controladores FastAPI del motor SQLite subyacente.

Ejecución:
    uvicorn src.api.api_server:app --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, status

from src.api.database import FlowRepositoryProtocol, SQLiteFlowRepository
from src.domain.schemas import HttpFlowCreate, HttpFlowRecord, TrafficStats

DEFAULT_DB_PATH = Path(
    os.getenv(
        "SITECRACK_DB_PATH",
        str(Path(__file__).resolve().parents[2] / "data" / "sitecrack_flows.db"),
    )
)


@lru_cache(maxsize=1)
def get_repository() -> FlowRepositoryProtocol:
    """Proveedor singleton del repositorio SQLite para Inyección de Dependencias."""
    return SQLiteFlowRepository(db_path=DEFAULT_DB_PATH)


app = FastAPI(
    title="Sitecrack Telemetry & Audit API",
    description=(
        "Backend RESTful ligero de almacenamiento e inspección pasiva de tráfico "
        "HTTP/S para la suite de auditoría web Sitecrack."
    ),
    version="1.0.0",
)


@app.get("/health", tags=["System"])
def health_check() -> dict[str, str]:
    """Verifica disponibilidad operativa del servicio Backend."""
    return {"status": "online", "service": "sitecrack-api", "version": "1.0.0"}


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
