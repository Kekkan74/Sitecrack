"""
Auditor Pasivo de Cabeceras de Seguridad HTTP y Sanitizador de Secretos.

Implementa el Principio de Responsabilidad Única (SRP) y Abierto/Cerrado (OCP):
nuevas reglas de auditoría pasiva pueden añadirse al registro de reglas sin
modificar la lógica del interceptor ni del servidor FastAPI.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Mapping

from src.domain.schemas import SecurityAuditResult, SecurityFinding, SecurityGrade


SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
    }
)


@dataclass(frozen=True)
class HeaderRule:
    """Regla declarativa para evaluar una cabecera defensiva HTTP."""

    header_name: str
    penalty: int
    severity: str  # "LOW" | "MEDIUM" | "HIGH"
    missing_message: str


DEFAULT_HEADER_RULES: tuple[HeaderRule, ...] = (
    HeaderRule(
        header_name="Strict-Transport-Security",
        penalty=25,
        severity="HIGH",
        missing_message="Ausencia de HSTS: expone la sesión a ataques de downgrade SSL/TLS.",
    ),
    HeaderRule(
        header_name="Content-Security-Policy",
        penalty=25,
        severity="HIGH",
        missing_message="Ausencia de CSP: incrementa la superficie ante inyección de scripts.",
    ),
    HeaderRule(
        header_name="X-Content-Type-Options",
        penalty=15,
        severity="MEDIUM",
        missing_message="Falta 'X-Content-Type-Options: nosniff' contra MIME-sniffing.",
    ),
    HeaderRule(
        header_name="X-Frame-Options",
        penalty=15,
        severity="MEDIUM",
        missing_message="Falta protección explícita contra Clickjacking (X-Frame-Options).",
    ),
    HeaderRule(
        header_name="Referrer-Policy",
        penalty=10,
        severity="LOW",
        missing_message="Falta Referrer-Policy para controlar fuga de URLs en cabeceras Referer.",
    ),
    HeaderRule(
        header_name="Permissions-Policy",
        penalty=10,
        severity="LOW",
        missing_message="Falta Permissions-Policy para restringir APIs sensibles del navegador.",
    ),
)


def sanitize_headers(headers: Mapping[str, str]) -> Dict[str, str]:
    """
    Ofusca valores de cabeceras sensibles (CWE-532) conservando la estructura
    para diagnóstico seguro sin almacenar credenciales en texto claro.
    """
    sanitized: Dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in SENSITIVE_HEADERS:
            prefix = value[:8] + "..." if len(value) > 8 else "***"
            sanitized[key] = f"[REDACTED:{prefix}]"
        else:
            sanitized[key] = value[:512]
    return sanitized


class PassiveSecurityAnalyzer:
    """Evalúa pasivamente la postura defensiva de una respuesta HTTP/S."""

    def __init__(self, rules: tuple[HeaderRule, ...] = DEFAULT_HEADER_RULES) -> None:
        self._rules = rules

    def evaluate(
        self, scheme: str, response_headers: Mapping[str, str]
    ) -> SecurityAuditResult:
        normalized = {k.lower(): v for k, v in response_headers.items()}
        score = 100
        missing: List[str] = []
        findings: List[SecurityFinding] = []

        if scheme.lower() != "https":
            score -= 30
            findings.append(
                SecurityFinding(
                    header="Transport-Layer",
                    severity="HIGH",
                    description="Tráfico transmitido sobre HTTP en texto claro sin cifrado TLS.",
                )
            )

        for rule in self._rules:
            key_lower = rule.header_name.lower()
            if key_lower not in normalized:
                score -= rule.penalty
                missing.append(rule.header_name)
                findings.append(
                    SecurityFinding(
                        header=rule.header_name,
                        severity=rule.severity,  # type: ignore[arg-type]
                        description=rule.missing_message,
                    )
                )

        server_banner = normalized.get("server", "")
        if any(char.isdigit() for char in server_banner):
            score -= 5
            findings.append(
                SecurityFinding(
                    header="Server",
                    severity="INFO",
                    description=f"Exposición de versión en cabecera Server ('{server_banner}').",
                )
            )

        bounded_score = max(0, min(100, score))
        grade = self._score_to_grade(bounded_score)
        return SecurityAuditResult(
            grade=grade,
            score=bounded_score,
            missing_headers=missing,
            findings=findings,
        )

    @staticmethod
    def _score_to_grade(score: int) -> SecurityGrade:
        if score >= 90:
            return "A"
        if score >= 75:
            return "B"
        if score >= 60:
            return "C"
        if score >= 40:
            return "D"
        return "F"
