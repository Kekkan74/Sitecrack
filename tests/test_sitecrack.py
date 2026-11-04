"""
Suite de Pruebas Unitarias y de Integración para Sitecrack.
Valida el bajo acoplamiento (DIP), alta cohesión (SRP), endurecimiento AppSec
(CWE-89, CWE-532) y formateadores visuales de accesibilidad.
"""

from __future__ import annotations

from pathlib import Path
from typing import List
from unittest.mock import MagicMock

from src.api.api_server import (
    clear_captured_flows,
    get_flow_detail,
    get_traffic_stats,
    health_check,
    ingest_flow,
    list_captured_flows,
)
from src.api.database import SQLiteFlowRepository
from src.core.proxy_core import MAX_PREVIEW_BYTES, SitecrackInterceptorAddon
from src.core.security_analyzer import PassiveSecurityAnalyzer, sanitize_headers
from src.domain.schemas import HttpFlowCreate
from src.ui.cli_app import (
    build_inspector_renderable,
    format_grade_badge,
    format_scheme_badge,
    format_status_badge,
)


def test_security_analyzer_grades_and_secret_redaction() -> None:
    analyzer = PassiveSecurityAnalyzer()

    # Caso 1: Respuesta HTTPS con todas las cabeceras defensivas -> Grado A
    hardened_headers = {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    res_a = analyzer.evaluate("https", hardened_headers)
    assert res_a.grade == "A"
    assert res_a.score == 100
    assert len(res_a.missing_headers) == 0

    # Caso 2: Respuesta HTTP plana sin cabeceras y con banner de versión -> Grado F
    weak_headers = {"Server": "Apache/2.4.49"}
    res_f = analyzer.evaluate("http", weak_headers)
    assert res_f.grade == "F"
    assert res_f.score == 0
    assert "Strict-Transport-Security" in res_f.missing_headers

    # Caso 3: Sanitización CWE-532 de cabeceras sensibles
    raw_req = {
        "Authorization": "Bearer secret_jwt_token_value_12345",
        "Cookie": "session_id=xyz987654321",
        "Accept": "application/json",
    }
    clean = sanitize_headers(raw_req)
    assert clean["Authorization"].startswith("[REDACTED:")
    assert "secret_jwt_token_value_12345" not in clean["Authorization"]
    assert clean["Cookie"].startswith("[REDACTED:")
    assert clean["Accept"] == "application/json"


def test_sqlite_repository_and_fastapi_controllers_integration(tmp_path: Path) -> None:
    test_db = tmp_path / "test_flows.db"
    repo = SQLiteFlowRepository(db_path=test_db)

    # 1. Health check
    health = health_check()
    assert health["status"] == "online"

    # 2. Ingestar un flujo mediante controlador FastAPI con DI
    analyzer = PassiveSecurityAnalyzer()
    audit = analyzer.evaluate("https", {"Strict-Transport-Security": "max-age=31536000"})
    payload = HttpFlowCreate(
        method="POST",
        scheme="https",
        host="api.example.org",
        path="/v1/login",
        url="https://api.example.org/v1/login",
        status_code=201,
        content_type="application/json",
        duration_ms=34.5,
        request_size=128,
        response_size=256,
        request_headers={"Host": "api.example.org"},
        response_headers={"Strict-Transport-Security": "max-age=31536000"},
        request_preview='{"user":"demo"}',
        response_preview='{"ok":true}',
        security_audit=audit,
    )

    created = ingest_flow(payload=payload, repo=repo)
    assert created.id == 1
    assert created.host == "api.example.org"

    # 3. Consultar lista filtrada, detalle individual y estadísticas
    flows = list_captured_flows(
        limit=50, offset=0, method="POST", host="example.org", min_status=200, repo=repo
    )
    assert len(flows) == 1
    assert flows[0].url == "https://api.example.org/v1/login"

    detail = get_flow_detail(flow_id=1, repo=repo)
    assert detail.status_code == 201

    stats = get_traffic_stats(repo=repo)
    assert stats.total_flows == 1
    assert stats.https_count == 1
    assert stats.error_count == 0

    # 4. Limpiar historial
    deleted = clear_captured_flows(repo=repo)
    assert deleted["deleted"] == 1
    assert get_traffic_stats(repo=repo).total_flows == 0


def test_interceptor_addon_decoupled_publisher_and_ram_bound() -> None:
    captured: List[HttpFlowCreate] = []

    class InMemoryPublisher:
        def publish(self, flow_dto: HttpFlowCreate) -> None:
            captured.append(flow_dto)

    addon = SitecrackInterceptorAddon(publisher=InMemoryPublisher())

    mock_flow = MagicMock()
    mock_flow.id = "flow-uuid-001"
    mock_flow.request.method = "get"
    mock_flow.request.scheme = "https"
    mock_flow.request.pretty_host = "secure.sitecrack.local"
    mock_flow.request.path = "/large-payload"
    mock_flow.request.pretty_url = "https://secure.sitecrack.local/large-payload"
    mock_flow.request.headers.items.return_value = [("Host", "secure.sitecrack.local")]
    mock_flow.request.raw_content = b"A" * (MAX_PREVIEW_BYTES + 1000)

    mock_flow.response.status_code = 200
    mock_flow.response.headers.get.return_value = "text/plain; charset=utf-8"
    mock_flow.response.headers.items.return_value = [
        ("Strict-Transport-Security", "max-age=31536000"),
        ("Content-Security-Policy", "default-src 'self'"),
    ]
    mock_flow.response.raw_content = b"B" * (MAX_PREVIEW_BYTES + 2000)

    addon.request(mock_flow)
    addon.response(mock_flow)

    assert len(captured) == 1
    dto = captured[0]
    assert dto.method == "GET"
    assert dto.host == "secure.sitecrack.local"
    assert "TRUNCADO" in dto.request_preview
    assert "TRUNCADO" in dto.response_preview
    assert len(dto.request_preview) < MAX_PREVIEW_BYTES + 120

    # Verificar que el panel inspector Rich construye sin errores
    record_mock = repo_record = dto.model_dump()
    from src.domain.schemas import HttpFlowRecord

    full_record = HttpFlowRecord(id=1, **record_mock)
    panel = build_inspector_renderable(full_record, high_contrast=True)
    assert panel is not None


def test_accessible_visual_formatters() -> None:
    ok_badge = format_status_badge(200, high_contrast=False)
    err_badge = format_status_badge(503, high_contrast=True)
    assert "✔ 200 OK" in ok_badge.plain
    assert "✖ 503 SERVER" in err_badge.plain

    https_badge = format_scheme_badge("https")
    http_badge = format_scheme_badge("http")
    assert "🔒 HTTPS" in https_badge.plain
    assert "🔓 HTTP" in http_badge.plain

    grade_badge = format_grade_badge("A", 95)
    assert "★ A" in grade_badge.plain
