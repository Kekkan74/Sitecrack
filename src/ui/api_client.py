"""
Cliente de Consumo REST Desacoplado para la Interfaz de Terminal (TUI).

Cumple con el Principio de Responsabilidad Única (SRP) y el Principio de
Inversión de Dependencias (DIP): la interfaz Textual/Rich consume el protocolo
`TelemetryClientProtocol`, permitiendo conmutar entre el backend FastAPI en vivo
y un proveedor de demostración determinista (`DemoTelemetryClient`) sin alterar la UI.
"""

from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import List, Optional, Protocol

from src.domain.schemas import (
    HttpFlowRecord,
    SecurityAuditResult,
    SecurityFinding,
    TrafficStats,
)

DEFAULT_API_BASE = os.getenv("SITECRACK_API_BASE", "http://127.0.0.1:8000")


class TelemetryClientProtocol(Protocol):
    """Abstracción de lectura/gestión de flujos para la capa de presentación."""

    def fetch_flows(
        self,
        limit: int = 100,
        host_filter: Optional[str] = None,
        method: Optional[str] = None,
    ) -> List[HttpFlowRecord]:
        ...

    def fetch_stats(self) -> TrafficStats:
        ...

    def clear_all(self) -> int:
        ...


class FastApiTelemetryClient:
    """Cliente HTTP ligero que consume los endpoints de `api_server.py`."""

    def __init__(
        self, base_url: str = DEFAULT_API_BASE, timeout: float = 2.0
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    def fetch_flows(
        self,
        limit: int = 100,
        host_filter: Optional[str] = None,
        method: Optional[str] = None,
    ) -> List[HttpFlowRecord]:
        params: dict[str, object] = {"limit": limit}
        if host_filter:
            params["host"] = host_filter
        if method:
            params["method"] = method

        query_str = urllib.parse.urlencode(params)
        url = f"{self._base_url}/api/v1/flows?{query_str}"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return [HttpFlowRecord.model_validate(item) for item in data]

    def fetch_stats(self) -> TrafficStats:
        url = f"{self._base_url}/api/v1/stats"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return TrafficStats.model_validate(data)

    def clear_all(self) -> int:
        url = f"{self._base_url}/api/v1/flows"
        req = urllib.request.Request(url, method="DELETE")
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return int(data.get("deleted", 0))


class DemoTelemetryClient:
    """
    Proveedor determinista en memoria para modo `--demo` o previsualización
    instantánea sin requerir tráfico real previo.
    """

    def __init__(self) -> None:
        self._flows: List[HttpFlowRecord] = [
            HttpFlowRecord(
                id=4,
                method="POST",
                scheme="http",
                host="legacy-portal.internal.local",
                path="/auth/session",
                url="http://legacy-portal.internal.local/auth/session",
                status_code=500,
                content_type="application/json",
                duration_ms=142.8,
                request_size=218,
                response_size=512,
                request_headers={
                    "Host": "legacy-portal.internal.local",
                    "Content-Type": "application/json",
                    "Authorization": "[REDACTED:Bearer e...]",
                },
                response_headers={
                    "Content-Type": "application/json",
                    "Server": "Apache/2.4.49 (Unix)",
                },
                request_preview='{"username": "auditor_soc", "mfa_step": 1}',
                response_preview='{"error": "Unhandled database exception in auth module"}',
                security_audit=SecurityAuditResult(
                    grade="F",
                    score=10,
                    missing_headers=[
                        "Strict-Transport-Security",
                        "Content-Security-Policy",
                        "X-Content-Type-Options",
                        "X-Frame-Options",
                    ],
                    findings=[
                        SecurityFinding(
                            header="Transport-Layer",
                            severity="HIGH",
                            description="Tráfico transmitido sobre HTTP en texto claro sin cifrado TLS.",
                        ),
                        SecurityFinding(
                            header="Strict-Transport-Security",
                            severity="HIGH",
                            description="Ausencia de HSTS: expone la sesión a ataques de downgrade SSL/TLS.",
                        ),
                        SecurityFinding(
                            header="Server",
                            severity="INFO",
                            description="Exposición de versión en cabecera Server ('Apache/2.4.49 (Unix)').",
                        ),
                    ],
                ),
                timestamp="2026-11-04T17:59:40Z",
            ),
            HttpFlowRecord(
                id=3,
                method="GET",
                scheme="https",
                host="app.corp-gateway.example",
                path="/dashboard/config.json",
                url="https://app.corp-gateway.example/dashboard/config.json",
                status_code=403,
                content_type="application/json",
                duration_ms=48.3,
                request_size=0,
                response_size=145,
                request_headers={
                    "Host": "app.corp-gateway.example",
                    "Cookie": "[REDACTED:session_...]",
                },
                response_headers={
                    "Content-Type": "application/json",
                    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                    "X-Content-Type-Options": "nosniff",
                },
                request_preview="",
                response_preview='{"status": "forbidden", "reason": "insufficient_scope"}',
                security_audit=SecurityAuditResult(
                    grade="C",
                    score=60,
                    missing_headers=[
                        "Content-Security-Policy",
                        "X-Frame-Options",
                    ],
                    findings=[
                        SecurityFinding(
                            header="Content-Security-Policy",
                            severity="HIGH",
                            description="Ausencia de CSP: incrementa la superficie ante inyección de scripts.",
                        ),
                        SecurityFinding(
                            header="X-Frame-Options",
                            severity="MEDIUM",
                            description="Falta protección explícita contra Clickjacking (X-Frame-Options).",
                        ),
                    ],
                ),
                timestamp="2026-11-04T17:59:25Z",
            ),
            HttpFlowRecord(
                id=2,
                method="GET",
                scheme="https",
                host="cdn.hardened-service.example",
                path="/assets/bundle.js",
                url="https://cdn.hardened-service.example/assets/bundle.js",
                status_code=200,
                content_type="application/javascript",
                duration_ms=19.4,
                request_size=0,
                response_size=18420,
                request_headers={"Host": "cdn.hardened-service.example"},
                response_headers={
                    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
                    "Content-Security-Policy": "default-src 'self'",
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "Referrer-Policy": "strict-origin-when-cross-origin",
                },
                request_preview="",
                response_preview="(() => { 'use strict'; console.info('Bundle initialized'); })();",
                security_audit=SecurityAuditResult(
                    grade="A",
                    score=90,
                    missing_headers=["Permissions-Policy"],
                    findings=[
                        SecurityFinding(
                            header="Permissions-Policy",
                            severity="LOW",
                            description="Falta Permissions-Policy para restringir APIs sensibles del navegador.",
                        )
                    ],
                ),
                timestamp="2026-11-04T17:59:12Z",
            ),
            HttpFlowRecord(
                id=1,
                method="GET",
                scheme="https",
                host="api.hardened-service.example",
                path="/v2/health",
                url="https://api.hardened-service.example/v2/health",
                status_code=200,
                content_type="application/json",
                duration_ms=11.2,
                request_size=0,
                response_size=64,
                request_headers={"Host": "api.hardened-service.example", "Accept": "application/json"},
                response_headers={
                    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
                    "Content-Security-Policy": "default-src 'none'",
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "Referrer-Policy": "no-referrer",
                    "Permissions-Policy": "geolocation=(), microphone=()",
                },
                request_preview="",
                response_preview='{"status": "healthy", "tls_version": "TLSv1.3"}',
                security_audit=SecurityAuditResult(
                    grade="A",
                    score=100,
                    missing_headers=[],
                    findings=[],
                ),
                timestamp="2026-11-04T17:59:01Z",
            ),
        ]

    def fetch_flows(
        self,
        limit: int = 100,
        host_filter: Optional[str] = None,
        method: Optional[str] = None,
    ) -> List[HttpFlowRecord]:
        results = list(self._flows)
        if host_filter:
            results = [f for f in results if host_filter.lower() in f.host.lower()]
        if method:
            results = [f for f in results if f.method.upper() == method.upper()]
        return results[:limit]

    def fetch_stats(self) -> TrafficStats:
        total = len(self._flows)
        if total == 0:
            return TrafficStats()
        https_c = sum(1 for f in self._flows if f.scheme == "https")
        http_c = total - https_c
        err_c = sum(1 for f in self._flows if f.status_code >= 400)
        low_sec = sum(1 for f in self._flows if f.security_audit.grade in ("D", "F"))
        avg_ms = round(sum(f.duration_ms for f in self._flows) / total, 2)
        return TrafficStats(
            total_flows=total,
            https_count=https_c,
            http_count=http_c,
            error_count=err_c,
            avg_duration_ms=avg_ms,
            low_security_count=low_sec,
        )

    def clear_all(self) -> int:
        count = len(self._flows)
        self._flows.clear()
        return count
