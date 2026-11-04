"""
Servicio Repetidor y Laboratorio de Remediación de Peticiones (repeater_service.py).

Diseño SOLID y Seguridad AppSec:
- SRP: Gestiona exclusivamente la reedición, ejecución controlada y comparación
  Antes vs. Después de una petición HTTP/S.
- DIP: Depende de `FlowRepositoryProtocol` y `PassiveSecurityAnalyzer`.
- Endurecimiento SSRF (CWE-918): Valida destinos de red bloqueando rangos privados,
  loopback y metadatos cloud (`169.254.169.254`) cuando se solicita modo en vivo.
"""

from __future__ import annotations

import ipaddress
import socket
import time
import urllib.error
import urllib.request
from typing import Dict, List, Literal, Optional, Tuple
from urllib.parse import urlparse

from src.api.database import FlowRepositoryProtocol
from src.core.proxy_core import MAX_PREVIEW_BYTES, _extract_safe_preview
from src.core.security_analyzer import PassiveSecurityAnalyzer, sanitize_headers
from src.domain.schemas import (
    HttpFlowCreate,
    RepeatFlowRequest,
    RepeatFlowResponse,
)

LAB_SUFFIXES = (".local", ".example", ".internal", ".test", ".invalid", ".es")


def is_safe_public_host(hostname: str) -> bool:
    """
    Guardrail Anti-SSRF (CWE-918): verifica que el host no apunte a loopback,
    redes internas RFC 1918 o endpoints de metadatos cloud (169.254.169.254).
    """
    clean_host = hostname.split(":")[0].strip().lower()
    if not clean_host or clean_host in ("localhost", "0.0.0.0"):
        return False
    if clean_host.endswith((".local", ".internal", ".example", ".test", ".invalid")):
        return False

    try:
        ip_obj = ipaddress.ip_address(clean_host)
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
        )
    except ValueError:
        pass

    try:
        resolved_ip = socket.gethostbyname(clean_host)
        ip_obj = ipaddress.ip_address(resolved_ip)
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
        )
    except OSError:
        return False


class RepeaterService:
    """Ejecuta peticiones modificadas y calcula la comparativa Antes vs. Después."""

    def __init__(
        self,
        repo: FlowRepositoryProtocol,
        analyzer: Optional[PassiveSecurityAnalyzer] = None,
    ) -> None:
        self._repo = repo
        self._analyzer = analyzer or PassiveSecurityAnalyzer()

    def execute_repeat(self, req: RepeatFlowRequest) -> RepeatFlowResponse:
        raw_url = req.url.strip()
        if "://" not in raw_url:
            raw_url = f"https://{raw_url}"

        parsed = urlparse(raw_url)
        scheme = (parsed.scheme or "https").lower()
        host = parsed.netloc or "sandbox.sitecrack.local"
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        normalized_url = f"{scheme}://{host}{path}"

        original_flow = (
            self._repo.get_flow_by_id(req.original_flow_id)
            if req.original_flow_id is not None
            else None
        )

        mode_used: Literal["sandbox", "live_http"] = "sandbox"
        resp_headers: Dict[str, str] = dict(req.response_headers)
        status_code = req.status_code
        duration_ms = 14.2
        resp_preview = ""
        resp_size = 0

        if req.live_network and is_safe_public_host(host):
            live_ok, live_data = self._try_live_request(
                method=req.method.upper(),
                url=normalized_url,
                req_headers=req.request_headers,
                req_body=req.request_body,
            )
            if live_ok:
                mode_used = "live_http"
                status_code, duration_ms, fetched_headers, resp_preview, resp_size = live_data
                # Combinar cabeceras reales con las cabeceras de remediación añadidas en el Repetidor
                merged = dict(fetched_headers)
                merged.update(req.response_headers)
                resp_headers = merged

        if mode_used == "sandbox":
            if not resp_headers and original_flow is not None:
                resp_headers = dict(original_flow.response_headers)
            if not resp_headers:
                resp_headers = {"Content-Type": "application/json"}
            if original_flow is not None and original_flow.response_preview:
                resp_preview = original_flow.response_preview
            else:
                resp_preview = (
                    f'{{"repetidor": "ok", "metodo": "{req.method.upper()}", '
                    f'"escudos_activos": {len(resp_headers)}}}'
                )
            resp_size = len(resp_preview.encode("utf-8"))

        audit_result = self._analyzer.evaluate(
            scheme=scheme,
            response_headers=resp_headers,
        )

        req_headers_clean = dict(req.request_headers)
        if "Host" not in req_headers_clean and "host" not in req_headers_clean:
            req_headers_clean["Host"] = host
        req_headers_clean["X-Sitecrack-Repeater"] = "Modified-Replay"

        content_type = (
            resp_headers.get("Content-Type")
            or resp_headers.get("content-type")
            or "application/json"
        ).split(";")[0].strip()

        req_body_bytes = req.request_body.encode("utf-8")

        flow_dto = HttpFlowCreate(
            method=req.method.upper(),
            scheme=scheme,
            host=host,
            path=path,
            url=normalized_url,
            status_code=status_code,
            content_type=content_type,
            duration_ms=duration_ms,
            request_size=len(req_body_bytes),
            response_size=resp_size,
            request_headers=sanitize_headers(req_headers_clean),
            response_headers=sanitize_headers(resp_headers),
            request_preview=_extract_safe_preview(req_body_bytes),
            response_preview=resp_preview[:MAX_PREVIEW_BYTES],
            security_audit=audit_result,
        )

        saved_flow = self._repo.save_flow(flow_dto)

        prev_grade = (
            original_flow.security_audit.grade if original_flow is not None else None
        )
        prev_score = (
            original_flow.security_audit.score if original_flow is not None else None
        )
        score_delta = (
            saved_flow.security_audit.score - prev_score
            if prev_score is not None
            else 0
        )

        fixed_headers: List[str] = []
        if original_flow is not None:
            old_missing = set(original_flow.security_audit.missing_headers)
            new_missing = set(saved_flow.security_audit.missing_headers)
            fixed_headers = sorted(list(old_missing - new_missing))
            if original_flow.scheme == "http" and saved_flow.scheme == "https":
                fixed_headers.insert(0, "HTTPS / TLS Cifrado")

        return RepeatFlowResponse(
            new_flow=saved_flow,
            original_flow_id=req.original_flow_id,
            previous_grade=prev_grade,
            previous_score=prev_score,
            score_delta=score_delta,
            fixed_headers=fixed_headers,
            execution_mode=mode_used,
        )

    @staticmethod
    def _try_live_request(
        method: str,
        url: str,
        req_headers: Dict[str, str],
        req_body: str,
    ) -> Tuple[bool, Tuple[int, float, Dict[str, str], str, int]]:
        start = time.perf_counter()
        data_bytes = (
            req_body.encode("utf-8")
            if req_body and method in ("POST", "PUT", "PATCH")
            else None
        )
        clean_headers = {
            k: v
            for k, v in req_headers.items()
            if not v.startswith("[REDACTED:")
        }
        request_obj = urllib.request.Request(
            url, data=data_bytes, headers=clean_headers, method=method
        )
        try:
            with urllib.request.urlopen(request_obj, timeout=3.5) as resp:
                elapsed = round((time.perf_counter() - start) * 1000.0, 2)
                raw = resp.read(MAX_PREVIEW_BYTES + 1)
                preview = _extract_safe_preview(raw)
                headers_dict = {k: v for k, v in resp.headers.items()}
                return True, (
                    int(resp.status),
                    elapsed,
                    headers_dict,
                    preview,
                    len(raw),
                )
        except urllib.error.HTTPError as http_err:
            elapsed = round((time.perf_counter() - start) * 1000.0, 2)
            raw = http_err.read(MAX_PREVIEW_BYTES) if http_err.fp else b""
            preview = _extract_safe_preview(raw)
            headers_dict = (
                {k: v for k, v in http_err.headers.items()}
                if http_err.headers
                else {}
            )
            return True, (
                int(http_err.code),
                elapsed,
                headers_dict,
                preview,
                len(raw),
            )
        except Exception:
            return False, (0, 0.0, {}, "", 0)
