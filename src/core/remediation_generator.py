"""
Generador Automático de Código de Remediación Defensiva (remediation_generator.py).

Diseño SOLID:
- SRP: Genera bloques de configuración listos para producción (FastAPI, Nginx,
  Apache y Node.js/Express) basados exactamente en las cabeceras de seguridad
  que le faltan a un flujo HTTP/S.
"""

from __future__ import annotations

from typing import Dict, List

RECOMMENDED_HEADER_VALUES: Dict[str, str] = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; object-src 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}


def generate_remediation_snippets(
    missing_headers: List[str],
    scheme: str = "https",
) -> Dict[str, str]:
    """
    Devuelve un diccionario con fragmentos de código para FastAPI, Nginx,
    Apache y Express.js que corrigen exactamente los escudos ausentes.
    """
    targets = (
        missing_headers
        if missing_headers
        else list(RECOMMENDED_HEADER_VALUES.keys())
    )
    active_pairs = [
        (h, RECOMMENDED_HEADER_VALUES.get(h, "nosniff")) for h in targets
    ]

    # 1. FastAPI / Starlette Middleware (Python)
    fastapi_lines = [
        "from fastapi import FastAPI, Request, Response",
        "",
        "app = FastAPI()",
        "",
        "@app.middleware('http')",
        "async def add_owasp_security_headers(request: Request, call_next) -> Response:",
        "    response: Response = await call_next(request)",
    ]
    for h_name, h_val in active_pairs:
        fastapi_lines.append(f'    response.headers["{h_name}"] = "{h_val}"')
    fastapi_lines.append("    return response")

    # 2. Nginx (nginx.conf / server block)
    nginx_lines = ["# Añadir dentro del bloque server { ... } en nginx.conf:"]
    if scheme.lower() != "https":
        nginx_lines.append("return 301 https://$host$request_uri;  # Forzar redirección a HTTPS")
    nginx_lines.append("server_tokens off;  # Ocultar versión exacta del servidor")
    for h_name, h_val in active_pairs:
        nginx_lines.append(f'add_header {h_name} "{h_val}" always;')

    # 3. Apache (.htaccess / httpd.conf)
    apache_lines = [
        "# Añadir en .htaccess o VirtualHost (requiere mod_headers):",
        "<IfModule mod_headers.c>",
    ]
    for h_name, h_val in active_pairs:
        apache_lines.append(f'    Header always set {h_name} "{h_val}"')
    apache_lines.append("</IfModule>")

    # 4. Node.js / Express Middleware
    express_lines = [
        "// Middleware en Express.js para añadir las cabeceras ausentes:",
        "app.use((req, res, next) => {",
    ]
    for h_name, h_val in active_pairs:
        express_lines.append(f'  res.setHeader("{h_name}", "{h_val}");')
    express_lines.extend(["  next();", "});"])

    return {
        "fastapi": "\n".join(fastapi_lines),
        "nginx": "\n".join(nginx_lines),
        "apache": "\n".join(apache_lines),
        "express": "\n".join(express_lines),
    }
