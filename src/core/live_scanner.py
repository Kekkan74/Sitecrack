"""
Auditor Pasivo en Vivo de Sitios Web Reales (live_scanner.py).

Diseño SOLID y Seguridad AppSec:
- SRP: Realiza una única petición HTTP/S de lectura pasiva (`GET` o `HEAD`) hacia
  una URL pública, mide la latencia real, extrae las cabeceras de seguridad y
  delega la evaluación en `PassiveSecurityAnalyzer`.
- Guardrail Anti-SSRF (CWE-918): Verifica tanto el host inicial como cualquier
  redirección HTTP (`301`/`302`/`307`/`308`) mediante `is_safe_public_host`,
  bloqueando IPs privadas, loopback o metadatos cloud (`169.254.169.254`).
- Eficiencia en RAM: Lee como máximo `MAX_PREVIEW_BYTES` (2048 bytes) del socket.
"""

from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
from typing import Dict, Optional
from urllib.parse import urlparse

from src.api.database import FlowRepositoryProtocol
from src.core.proxy_core import MAX_PREVIEW_BYTES, _extract_safe_preview
from src.core.repeater_service import is_safe_public_host
from src.core.security_analyzer import PassiveSecurityAnalyzer, sanitize_headers
from src.domain.schemas import HttpFlowCreate, HttpFlowRecord


class _SSRFProtectedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Bloquea redirecciones maliciosas hacia redes internas o loopback (CWE-918)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        parsed = urlparse(newurl)
        target_host = parsed.netloc
        if not is_safe_public_host(target_host):
            raise ValueError(
                f"Redirección bloqueada por protección Anti-SSRF hacia: {target_host}"
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class LiveUrlScanner:
    """Ejecuta una auditoría pasiva en tiempo real sobre una URL pública."""

    def __init__(
        self,
        repo: FlowRepositoryProtocol,
        analyzer: Optional[PassiveSecurityAnalyzer] = None,
        timeout_seconds: float = 6.0,
    ) -> None:
        self._repo = repo
        self._analyzer = analyzer or PassiveSecurityAnalyzer()
        self._timeout = timeout_seconds

    def scan_public_url(
        self,
        raw_url: str,
        method: str = "GET",
    ) -> HttpFlowRecord:
        cleaned = raw_url.strip()
        if "://" not in cleaned:
            cleaned = f"https://{cleaned}"

        parsed = urlparse(cleaned)
        scheme = (parsed.scheme or "https").lower()
        if scheme not in ("http", "https"):
            raise ValueError("Solo se permiten esquemas HTTP o HTTPS.")

        host = parsed.netloc
        if not host or not is_safe_public_host(host):
            raise ValueError(
                f"El dominio '{host or cleaned}' no es un host público válido o está bloqueado por seguridad Anti-SSRF."
            )

        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        normalized_url = f"{scheme}://{host}{path}"

        req_headers = {
            "Host": host,
            "User-Agent": "Sitecrack-Passive-Security-Auditor/2.2 (+https://github.com/Kekkan74/Sitecrack)",
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
            "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
        }

        safe_method = "HEAD" if method.upper() == "HEAD" else "GET"
        request_obj = urllib.request.Request(
            normalized_url,
            headers=req_headers,
            method=safe_method,
        )

        ctx = ssl.create_default_context()
        try:
            import certifi  # type: ignore[import-not-found]

            ctx.load_verify_locations(cafile=certifi.where())
        except Exception:
            pass

        opener = urllib.request.build_opener(
            _SSRFProtectedRedirectHandler(),
            urllib.request.HTTPSHandler(context=ctx),
        )

        start_t = time.perf_counter()
        status_code = 200
        resp_headers: Dict[str, str] = {}
        raw_chunk = b""

        try:
            with opener.open(request_obj, timeout=self._timeout) as resp:
                duration_ms = round((time.perf_counter() - start_t) * 1000.0, 2)
                status_code = int(resp.status)
                resp_headers = {k: v for k, v in resp.headers.items()}
                raw_chunk = resp.read(MAX_PREVIEW_BYTES + 1)
        except urllib.error.HTTPError as http_err:
            duration_ms = round((time.perf_counter() - start_t) * 1000.0, 2)
            status_code = int(http_err.code)
            if http_err.headers:
                resp_headers = {k: v for k, v in http_err.headers.items()}
            if http_err.fp:
                raw_chunk = http_err.read(MAX_PREVIEW_BYTES)
        except urllib.error.URLError as url_err:
            if "CERTIFICATE_VERIFY_FAILED" in str(url_err):
                # Si el almacén local de Windows no tiene la CA intermedia o el reloj
                # del sistema difiere, permitimos inspeccionar las cabeceras pasivamente
                fallback_ctx = ssl._create_unverified_context()
                fallback_opener = urllib.request.build_opener(
                    _SSRFProtectedRedirectHandler(),
                    urllib.request.HTTPSHandler(context=fallback_ctx),
                )
                with fallback_opener.open(request_obj, timeout=self._timeout) as resp:
                    duration_ms = round((time.perf_counter() - start_t) * 1000.0, 2)
                    status_code = int(resp.status)
                    resp_headers = {k: v for k, v in resp.headers.items()}
                    raw_chunk = resp.read(MAX_PREVIEW_BYTES + 1)
            else:
                raise RuntimeError(
                    f"No se pudo conectar con '{normalized_url}': {url_err}"
                ) from url_err
        except Exception as exc:
            raise RuntimeError(
                f"No se pudo conectar con '{normalized_url}': {exc}"
            ) from exc

        audit = self._analyzer.evaluate(
            scheme=scheme,
            response_headers=resp_headers,
        )

        content_type = (
            resp_headers.get("Content-Type")
            or resp_headers.get("content-type")
            or "text/html"
        ).split(";")[0].strip()

        flow_dto = HttpFlowCreate(
            method=safe_method,
            scheme=scheme,
            host=host,
            path=path,
            url=normalized_url,
            status_code=status_code,
            content_type=content_type,
            duration_ms=duration_ms,
            request_size=0,
            response_size=len(raw_chunk),
            request_headers=sanitize_headers(req_headers),
            response_headers=sanitize_headers(resp_headers),
            request_preview="",
            response_preview=_extract_safe_preview(raw_chunk),
            security_audit=audit,
        )

        return self._repo.save_flow(flow_dto)
