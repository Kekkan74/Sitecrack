"""
Motor de Privacidad, Anonimato y Desinfección de Rastreo (stealth_engine.py).

Diseño SOLID y Privacidad por Defecto:
- SRP: Responsable exclusivo de desinfectar URLs (eliminando parámetros espía),
  normalizar cabeceras HTTP (spoofing de User-Agent, supresión de Referer y
  eliminación de Client Hints) y configurar túneles upstream SOCKS5 / Tor.
- DIP: La configuración y el motor se desacoplan mediante esquemas Pydantic y
  se integran limpiamente en el pipeline del proxy y el escáner.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from pydantic import BaseModel, Field

# Parámetros de rastreo y fingerprinting comunes en URLs
KNOWN_TRACKING_PARAMS: Set[str] = {
    # UTMs y analítica general
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "utm_id",
    "utm_name",
    "utm_reader",
    # Google Ads y Analytics
    "gclid",
    "dclid",
    "gbraid",
    "wbraid",
    "_ga",
    "_gl",
    "gad_source",
    # Facebook / Meta
    "fbclid",
    "fbc",
    "fbp",
    # Microsoft / Bing
    "msclkid",
    # Twitter / X
    "twclid",
    # Email / Newsletters
    "mc_eid",
    "mc_cid",
    # Redes sociales y compartición
    "ref_src",
    "ref_url",
    "igshid",
    "si",
    "spm",
    "scm",
}

# Cabeceras de telemetría y Client Hints que exponen detalles de hardware
CLIENT_HINTS_HEADERS: Set[str] = {
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-ch-ua-model",
    "sec-ch-ua-arch",
    "sec-ch-ua-full-version",
    "sec-ch-ua-full-version-list",
    "sec-ch-ua-bitness",
    "x-client-data",
}

# User-Agent neutral y genérico (Firma de Tor Browser ESR / Firefox Privacy)
DEFAULT_ANONYMOUS_USER_AGENT: str = (
    "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"
)


class StealthConfig(BaseModel):
    """Configuración del Modo Sigilo y Anonimato."""

    enabled: bool = Field(default=True, description="Activa o desactiva el modo anónimo.")
    strip_tracking_params: bool = Field(
        default=True, description="Limpia parámetros espía de URLs (fbclid, utm_*, etc.)."
    )
    strip_referer: bool = Field(
        default=True, description="Suprime la cabecera Referer para no filtrar el origen."
    )
    strip_client_hints: bool = Field(
        default=True,
        description="Elimina cabeceras Sec-CH-UA que identifican hardware y modelo.",
    )
    spoof_user_agent: bool = Field(
        default=True,
        description="Sustituye el User-Agent específico por una firma anónima uniforme.",
    )
    custom_user_agent: str = Field(
        default=DEFAULT_ANONYMOUS_USER_AGENT,
        description="User-Agent a emplear cuando spoof_user_agent está activo.",
    )
    upstream_proxy: Optional[str] = Field(
        default="socks5h://127.0.0.1:9050",
        description="Proxy upstream opcional (ej. Tor en socks5h://127.0.0.1:9050).",
    )


class AnonymityAuditReport(BaseModel):
    """Diagnóstico del grado de privacidad de una petición."""

    anonymity_score: int = Field(..., ge=0, le=100)
    verdict: str
    leaked_attributes: List[str] = Field(default_factory=list)
    remediations_applied: List[str] = Field(default_factory=list)


class StealthEngine:
    """Motor central de desinfección de tráfico y protección de privacidad."""

    def __init__(self, config: Optional[StealthConfig] = None) -> None:
        self.config: StealthConfig = config or StealthConfig()
        self.total_tracking_params_stripped: int = 0
        self.total_headers_anonymized: int = 0

    def update_config(self, new_config: StealthConfig) -> None:
        """Actualiza la configuración en caliente."""
        self.config = new_config

    def sanitize_url(self, raw_url: str) -> Tuple[str, List[str]]:
        """
        Elimina de la URL todos los parámetros espía de seguimiento (utm_*, fbclid, etc.).
        Devuelve la URL limpia y la lista de parámetros neutralizados.
        """
        if not self.config.enabled or not self.config.strip_tracking_params:
            return raw_url, []

        parsed = urlparse(raw_url)
        if not parsed.query:
            return raw_url, []

        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        cleaned_pairs: List[Tuple[str, str]] = []
        stripped: List[str] = []

        for k, v in pairs:
            k_lower = k.lower().strip()
            if k_lower in KNOWN_TRACKING_PARAMS or k_lower.startswith("utm_"):
                stripped.append(k)
            else:
                cleaned_pairs.append((k, v))

        if not stripped:
            return raw_url, []

        self.total_tracking_params_stripped += len(stripped)
        new_query = urlencode(cleaned_pairs)
        cleaned_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment,
        ))
        return cleaned_url, stripped

    def sanitize_request_headers(
        self, headers: Dict[str, str]
    ) -> Tuple[Dict[str, str], List[str]]:
        """
        Normaliza y desinfecta las cabeceras HTTP de salida:
        - Suprime Referer
        - Elimina Client Hints (Sec-CH-UA*)
        - Aplica User-Agent anónimo neutro
        Devuelve el diccionario limpio y la lista de acciones aplicadas.
        """
        if not self.config.enabled:
            return dict(headers), []

        cleaned: Dict[str, str] = {}
        applied_actions: List[str] = []

        for k, v in headers.items():
            k_lower = k.lower().strip()

            # 1. Supresión de Referer
            if self.config.strip_referer and k_lower in ("referer", "referrer"):
                applied_actions.append(f"Cabecera '{k}' suprimida (Anti-Leaking)")
                self.total_headers_anonymized += 1
                continue

            # 2. Supresión de Client Hints
            if self.config.strip_client_hints and (
                k_lower in CLIENT_HINTS_HEADERS or k_lower.startswith("sec-ch-ua")
            ):
                applied_actions.append(f"Client Hint '{k}' eliminado (Anti-Fingerprinting)")
                self.total_headers_anonymized += 1
                continue

            # 3. User-Agent
            if self.config.spoof_user_agent and k_lower == "user-agent":
                cleaned[k] = self.config.custom_user_agent
                if v != self.config.custom_user_agent:
                    applied_actions.append("User-Agent normalizado a firma neutral")
                    self.total_headers_anonymized += 1
                continue

            cleaned[k] = v

        # Si no había User-Agent y está activo el spoofing, se añade uno neutral
        if self.config.spoof_user_agent and not any(k.lower() == "user-agent" for k in cleaned):
            cleaned["User-Agent"] = self.config.custom_user_agent
            applied_actions.append("User-Agent anónimo inyectado")
            self.total_headers_anonymized += 1

        return cleaned, applied_actions

    def evaluate_request_privacy(
        self, url: str, headers: Dict[str, str]
    ) -> AnonymityAuditReport:
        """
        Evalúa el nivel de anonimato de una petición antes de salir a la red.
        """
        leaks: List[str] = []
        parsed = urlparse(url)
        if parsed.query:
            for k, _ in parse_qsl(parsed.query):
                if k.lower() in KNOWN_TRACKING_PARAMS or k.lower().startswith("utm_"):
                    leaks.append(f"Parámetro de rastreo en URL: {k}")

        for k in headers.keys():
            k_lower = k.lower()
            if k_lower in ("referer", "referrer"):
                leaks.append("Cabecera Referer expuesta (revela página de procedencia)")
            elif k_lower in CLIENT_HINTS_HEADERS or k_lower.startswith("sec-ch-ua"):
                leaks.append(f"Client Hint expuesto: {k} (expone modelo y arquitectura)")

        score = max(0, 100 - (len(leaks) * 20))
        if score >= 90:
            verdict = "Nivel de Privacidad Óptimo: petición libre de rastreadores y huella única."
        elif score >= 60:
            verdict = "Nivel Medio: contiene metadatos menores que facilitan el tracking."
        else:
            verdict = "Nivel Débil: expone parámetros de rastreo o huella de hardware del navegador."

        return AnonymityAuditReport(
            anonymity_score=score,
            verdict=verdict,
            leaked_attributes=leaks,
        )


# Instancia compartida por defecto
default_stealth_engine = StealthEngine()
