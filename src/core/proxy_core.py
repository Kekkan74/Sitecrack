"""
Core de Red (Interceptor HTTP/S basado en mitmproxy) - proxy_core.py

Diseño SOLID:
- SRP: Este módulo solo extrae telemetría de flujos mitmproxy y delega la
  evaluación de seguridad a `PassiveSecurityAnalyzer` y el transporte a `FlowPublisher`.
- DIP: Depende del protocolo abstracto `FlowPublisherProtocol`, permitiendo
  inyectar publicadores en memoria para tests o transporte HTTP asíncrono en producción.
- Eficiencia en RAM: Acota estrictamente la lectura de payloads (`MAX_PREVIEW_BYTES = 2048`)
  evitando desbordamiento de memoria ante descargas de archivos pesados.

Ejecución:
    mitmdump -s src/core/proxy_core.py --listen-host 127.0.0.1 -p 8080
"""

from __future__ import annotations

import logging
import os
import queue
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional, Protocol

if TYPE_CHECKING:
    from mitmproxy import http

# Garantizar resolución de imports cuando mitmdump invoca el script directamente
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core.security_analyzer import PassiveSecurityAnalyzer, sanitize_headers
from src.domain.schemas import HttpFlowCreate

logger = logging.getLogger("sitecrack.proxy")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

MAX_PREVIEW_BYTES: int = 2048
DEFAULT_BACKEND_URL: str = os.getenv(
    "SITECRACK_API_URL", "http://127.0.0.1:8000/api/v1/flows"
)


class FlowPublisherProtocol(Protocol):
    """Abstracción (DIP) para publicar flujos capturados hacia el backend."""

    def publish(self, flow_dto: HttpFlowCreate) -> None:
        """Envía el DTO de flujo hacia el consumidor configurado."""


class AsyncQueueHttpPublisher:
    """
    Publicador HTTP no bloqueante con cola acotada en memoria (`maxsize=500`).
    Protege el hilo principal del proxy y mantiene el consumo de RAM constante.
    """

    def __init__(
        self,
        endpoint_url: str = DEFAULT_BACKEND_URL,
        max_queue_size: int = 500,
        timeout_seconds: float = 2.5,
    ) -> None:
        self._endpoint_url = endpoint_url
        self._timeout = timeout_seconds
        self._queue: queue.Queue[Optional[HttpFlowCreate]] = queue.Queue(
            maxsize=max_queue_size
        )
        self._stop_event = threading.Event()
        self._worker = threading.Thread(
            target=self._consume_loop,
            name="sitecrack-telemetry-sender",
            daemon=True,
        )
        self._worker.start()

    def publish(self, flow_dto: HttpFlowCreate) -> None:
        try:
            self._queue.put_nowait(flow_dto)
        except queue.Full:
            logger.warning(
                "Cola de telemetría llena; descartando flujo %s para preservar RAM.",
                flow_dto.url,
            )

    def _consume_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                item = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue

            if item is None:
                self._queue.task_done()
                break

            try:
                body_bytes = item.model_dump_json().encode("utf-8")
                req = urllib.request.Request(
                    self._endpoint_url,
                    data=body_bytes,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                    if resp.status >= 400:
                        logger.debug(
                            "Backend devolvió HTTP %d al registrar flujo.",
                            resp.status,
                        )
            except (urllib.error.URLError, OSError) as exc:
                logger.debug("Backend FastAPI no disponible aún: %s", exc)
            finally:
                self._queue.task_done()

    def close(self) -> None:
        self._stop_event.set()
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass


def _extract_safe_preview(raw_content: Optional[bytes]) -> str:
    """Decodifica únicamente los primeros `MAX_PREVIEW_BYTES` sin duplicar buffers grandes."""
    if not raw_content:
        return ""
    chunk = raw_content[:MAX_PREVIEW_BYTES]
    text = chunk.decode("utf-8", errors="replace")
    if len(raw_content) > MAX_PREVIEW_BYTES:
        return f"{text}\n... [TRUNCADO: {len(raw_content)} bytes totales]"
    return text


class SitecrackInterceptorAddon:
    """
    Addon principal de mitmproxy.
    Intercepta peticiones/respuestas, ejecuta auditoría pasiva de cabeceras y
    despacha metadatos al backend desacoplado.
    """

    def __init__(
        self,
        publisher: Optional[FlowPublisherProtocol] = None,
        analyzer: Optional[PassiveSecurityAnalyzer] = None,
    ) -> None:
        self._publisher: FlowPublisherProtocol = publisher or AsyncQueueHttpPublisher()
        self._analyzer: PassiveSecurityAnalyzer = analyzer or PassiveSecurityAnalyzer()
        self._flow_timers: dict[str, float] = {}

    def request(self, flow: http.HTTPFlow | Any) -> None:
        """Hook disparado al recibir los encabezados/cuerpo de la petición."""
        self._flow_timers[flow.id] = time.perf_counter()

    def response(self, flow: http.HTTPFlow | Any) -> None:
        """Hook disparado al completarse la respuesta del servidor remoto."""
        if getattr(flow, "response", None) is None:
            return

        start_time = self._flow_timers.pop(flow.id, None)
        if start_time is not None:
            duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        elif (
            getattr(flow.request, "timestamp_start", None) is not None
            and getattr(flow.response, "timestamp_end", None) is not None
        ):
            duration_ms = round(
                max(
                    0.0,
                    (flow.response.timestamp_end - flow.request.timestamp_start)
                    * 1000.0,
                ),
                2,
            )
        else:
            duration_ms = 0.0

        req_headers_raw = dict(flow.request.headers.items(multi=False))
        resp_headers_raw = dict(flow.response.headers.items(multi=False))

        audit_result = self._analyzer.evaluate(
            scheme=flow.request.scheme,
            response_headers=resp_headers_raw,
        )

        content_type = (
            flow.response.headers.get("content-type", "unknown")
            .split(";")[0]
            .strip()
        )
        req_bytes = flow.request.raw_content or b""
        resp_bytes = flow.response.raw_content or b""

        flow_dto = HttpFlowCreate(
            method=flow.request.method.upper(),
            scheme=flow.request.scheme.lower(),
            host=flow.request.pretty_host,
            path=flow.request.path or "/",
            url=flow.request.pretty_url,
            status_code=int(flow.response.status_code),
            content_type=content_type or "unknown",
            duration_ms=duration_ms,
            request_size=len(req_bytes),
            response_size=len(resp_bytes),
            request_headers=sanitize_headers(req_headers_raw),
            response_headers=sanitize_headers(resp_headers_raw),
            request_preview=_extract_safe_preview(req_bytes),
            response_preview=_extract_safe_preview(resp_bytes),
            security_audit=audit_result,
        )

        self._publisher.publish(flow_dto)
        logger.info(
            "[%s] %s -> HTTP %d (%s ms | SecGrade: %s)",
            flow_dto.method,
            flow_dto.url,
            flow_dto.status_code,
            flow_dto.duration_ms,
            flow_dto.security_audit.grade,
        )


# Registro estándar de addons requerido por mitmproxy / mitmdump
addons = [SitecrackInterceptorAddon()]
