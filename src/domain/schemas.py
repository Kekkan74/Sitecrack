"""
Capa de Dominio (Contratos de Datos y Entidades Inmutables).

Cumple con el Principio de Responsabilidad Única (SRP) y el Principio de Inversión
de Dependencias (DIP): tanto el motor de red (mitmproxy), como el servidor API (FastAPI),
el servicio Repetidor y la interfaz gráfica dependen de estas abstracciones de dominio
sin acoplarse entre sí.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


SecurityGrade = Literal["A", "B", "C", "D", "F"]


class SecurityFinding(BaseModel):
    """Hallazgo pasivo sobre cabeceras o configuración de seguridad HTTP."""

    model_config = ConfigDict(frozen=True)

    header: str = Field(..., description="Nombre de la cabecera o control evaluado")
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH"] = Field(
        ..., description="Nivel de impacto en defensa en profundidad"
    )
    description: str = Field(..., description="Explicación concisa y accionable")


class SecurityAuditResult(BaseModel):
    """Resultado de la evaluación pasiva de seguridad sobre un flujo HTTP."""

    model_config = ConfigDict(frozen=True)

    grade: SecurityGrade = Field(..., description="Calificación global (A - F)")
    score: int = Field(..., ge=0, le=100, description="Puntuación numérica (0 - 100)")
    missing_headers: List[str] = Field(
        default_factory=list, description="Cabeceras defensivas ausentes"
    )
    findings: List[SecurityFinding] = Field(
        default_factory=list, description="Lista detallada de hallazgos pasivos"
    )


class HttpFlowCreate(BaseModel):
    """DTO de entrada emitido por el interceptor hacia el Backend API."""

    model_config = ConfigDict(extra="ignore")

    method: str = Field(..., min_length=1, max_length=16, examples=["GET", "POST"])
    scheme: str = Field(..., min_length=1, max_length=10, examples=["https", "http"])
    host: str = Field(..., min_length=1, max_length=255, examples=["api.example.com"])
    path: str = Field(..., min_length=1, max_length=2048, examples=["/v1/users"])
    url: str = Field(..., min_length=1, max_length=4096)
    status_code: int = Field(..., ge=100, le=599, examples=[200])
    content_type: str = Field(default="unknown", max_length=256)
    duration_ms: float = Field(default=0.0, ge=0.0)
    request_size: int = Field(default=0, ge=0)
    response_size: int = Field(default=0, ge=0)
    request_headers: Dict[str, str] = Field(default_factory=dict)
    response_headers: Dict[str, str] = Field(default_factory=dict)
    request_preview: str = Field(
        default="",
        max_length=4096,
        description="Vista previa acotada del cuerpo de petición (protección de RAM)",
    )
    response_preview: str = Field(
        default="",
        max_length=4096,
        description="Vista previa acotada del cuerpo de respuesta (protección de RAM)",
    )
    security_audit: SecurityAuditResult
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class HttpFlowRecord(HttpFlowCreate):
    """Entidad persistida con identificador único asignado por el repositorio."""

    id: int = Field(..., ge=1, description="ID secuencial en SQLite")


class TrafficStats(BaseModel):
    """Métricas agregadas en tiempo real para el banner superior."""

    total_flows: int = 0
    https_count: int = 0
    http_count: int = 0
    error_count: int = 0
    avg_duration_ms: float = 0.0
    low_security_count: int = 0


class RepeatFlowRequest(BaseModel):
    """Solicitud del módulo Repetidor para modificar y reenviar una petición."""

    original_flow_id: Optional[int] = Field(
        default=None, description="ID del flujo original para comparar Antes vs Después"
    )
    method: str = Field(default="GET", min_length=1, max_length=16)
    url: str = Field(..., min_length=4, max_length=4096)
    request_headers: Dict[str, str] = Field(default_factory=dict)
    response_headers: Dict[str, str] = Field(default_factory=dict)
    request_body: str = Field(default="", max_length=4096)
    status_code: int = Field(default=200, ge=100, le=599)
    live_network: bool = Field(
        default=False,
        description="Si es True, intenta consultar la URL real validando protección anti-SSRF",
    )


class RepeatFlowResponse(BaseModel):
    """Resultado devuelto por el Repetidor con comparativa Antes vs Después."""

    new_flow: HttpFlowRecord
    original_flow_id: Optional[int] = None
    previous_grade: Optional[SecurityGrade] = None
    previous_score: Optional[int] = None
    score_delta: int = 0
    fixed_headers: List[str] = Field(default_factory=list)
    execution_mode: Literal["sandbox", "live_http"] = "sandbox"
