"""
Suite de Pruebas Unitarias y de Integración para Sitecrack (App Gráfica + API + Core).
Valida el bajo acoplamiento (DIP), alta cohesión (SRP), endurecimiento AppSec
(CWE-89, CWE-532), simulador visual y formateadores de accesibilidad.
"""

from __future__ import annotations

from pathlib import Path
from typing import List
from unittest.mock import MagicMock

from src.api.api_server import (
    LiveScanRequest,
    SimulationRequest,
    clear_captured_flows,
    export_html_report,
    export_json_report,
    get_flow_detail,
    get_flow_remediation_code,
    get_traffic_stats,
    health_check,
    ingest_flow,
    list_captured_flows,
    repeat_and_audit_flow,
    scan_live_website,
    seed_demo_flows,
    serve_graphical_app,
    simulate_custom_flow,
)
from src.api.database import SQLiteFlowRepository
from src.core.proxy_core import MAX_PREVIEW_BYTES, SitecrackInterceptorAddon
from src.core.repeater_service import is_safe_public_host
from src.core.security_analyzer import PassiveSecurityAnalyzer, sanitize_headers
from src.domain.schemas import HttpFlowCreate, HttpFlowRecord, RepeatFlowRequest
from src.ui.cli_app import (
    build_inspector_renderable,
    format_grade_badge,
    format_scheme_badge,
    format_status_badge,
)
from src.ui.gui_app import HEADER_EXPLANATIONS


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

    # 1. Health check & Graphical App HTML file check
    health = health_check()
    assert health["status"] == "online"
    html_resp = serve_graphical_app()
    assert Path(html_resp.path).exists()

    # 2. Seed de demostración y simulador interactivo de la App Gráfica
    seeded = seed_demo_flows(repo=repo)
    assert len(seeded) == 4

    sim_record = simulate_custom_flow(
        sim=SimulationRequest(
            url="https://panel.empresa.es/pagos",
            method="POST",
            status_code=200,
            preset="hardened",
        ),
        repo=repo,
    )
    assert sim_record.security_audit.grade == "A"
    assert sim_record.host == "panel.empresa.es"

    # 3. Consultar lista filtrada, detalle individual y estadísticas
    flows = list_captured_flows(
        limit=50,
        offset=0,
        method="POST",
        host="panel.empresa.es",
        min_status=200,
        repo=repo,
    )
    assert len(flows) == 1
    assert flows[0].url == "https://panel.empresa.es/pagos"

    detail = get_flow_detail(flow_id=sim_record.id, repo=repo)
    assert detail.status_code == 200

    stats = get_traffic_stats(repo=repo)
    assert stats.total_flows == 5

    # 4. Limpiar historial
    deleted = clear_captured_flows(repo=repo)
    assert deleted["deleted"] == 5
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

    full_record = HttpFlowRecord(id=1, **dto.model_dump())
    panel = build_inspector_renderable(full_record, high_contrast=True)
    assert panel is not None
    assert "Strict-Transport-Security" in HEADER_EXPLANATIONS


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


def test_repeater_before_after_comparison_and_ssrf_guard(tmp_path: Path) -> None:
    # 1. Verificar guardrail Anti-SSRF (CWE-918)
    assert is_safe_public_host("127.0.0.1") is False
    assert is_safe_public_host("localhost") is False
    assert is_safe_public_host("169.254.169.254") is False
    assert is_safe_public_host("192.168.1.10") is False
    assert is_safe_public_host("portal.internal.local") is False

    # 2. Flujo vulnerable inicial (HTTP plano sin escudos -> Nota F)
    repo = SQLiteFlowRepository(db_path=tmp_path / "repeater.db")
    vuln_flow = simulate_custom_flow(
        sim=SimulationRequest(
            url="http://legacy-portal.internal.local/auth/session",
            method="POST",
            status_code=500,
            preset="vulnerable",
        ),
        repo=repo,
    )
    assert vuln_flow.security_audit.grade == "F"
    assert vuln_flow.security_audit.score == 0

    # 3. Ejecutar el Repetidor pasando a HTTPS e inyectando todos los escudos OWASP
    rep_result = repeat_and_audit_flow(
        payload=RepeatFlowRequest(
            original_flow_id=vuln_flow.id,
            method="POST",
            url="https://legacy-portal.internal.local/auth/session",
            status_code=200,
            request_headers={"Host": "legacy-portal.internal.local"},
            response_headers={
                "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=(), microphone=()",
            },
            request_body='{"username": "auditor_soc"}',
            live_network=False,
        ),
        repo=repo,
    )

    assert rep_result.previous_grade == "F"
    assert rep_result.new_flow.security_audit.grade == "A"
    assert rep_result.new_flow.security_audit.score == 100
    assert rep_result.score_delta == 100
    assert "HTTPS / TLS Cifrado" in rep_result.fixed_headers
    assert "Strict-Transport-Security" in rep_result.fixed_headers

    # 4. Verificar exportación de Informe Ejecutivo HTML y JSON
    html_report = export_html_report(repo=repo)
    assert "Informe Ejecutivo de Auditoría Web" in html_report.body.decode("utf-8")

    json_report = export_json_report(repo=repo)
    assert json_report["stats"]["total_flows"] == 2  # type: ignore[index]


def test_remediation_code_generator_for_stacks(tmp_path: Path) -> None:
    repo = SQLiteFlowRepository(db_path=tmp_path / "remediation.db")
    vuln_flow = simulate_custom_flow(
        sim=SimulationRequest(
            url="https://tienda.ejemplo.es/checkout",
            method="GET",
            status_code=200,
            preset="vulnerable",
        ),
        repo=repo,
    )

    remediation = get_flow_remediation_code(flow_id=vuln_flow.id, repo=repo)
    assert "Strict-Transport-Security" in remediation["missing_headers"]  # type: ignore[operator]
    assert "@app.middleware" in str(remediation["fastapi"])
    assert "add_header Strict-Transport-Security" in str(remediation["nginx"])
    assert "Header always set" in str(remediation["apache"])
    assert "app.use" in str(remediation["express"])


def test_live_website_scanner_ssrf_block_and_real_public_web(tmp_path: Path) -> None:
    import pytest
    from fastapi import HTTPException

    repo = SQLiteFlowRepository(db_path=tmp_path / "live_scan.db")

    # 1. Verificar que IPs internas / loopback son bloqueadas por Anti-SSRF (CWE-918)
    with pytest.raises(HTTPException) as exc_info:
        scan_live_website(
            payload=LiveScanRequest(url="http://127.0.0.1:8000/health", method="GET"),
            repo=repo,
        )
    assert exc_info.value.status_code == 403

    # 2. Auditar webs públicas reales en vivo (example.com y github.com)
    real_example = scan_live_website(
        payload=LiveScanRequest(url="https://example.com", method="GET"),
        repo=repo,
    )
    assert real_example.host == "example.com"
    assert real_example.status_code == 200
    assert real_example.duration_ms > 0
    assert real_example.security_audit.grade in ("A", "B", "C", "D", "F")

    real_github = scan_live_website(
        payload=LiveScanRequest(url="https://github.com", method="GET"),
        repo=repo,
    )
    assert "github.com" in real_github.host
    assert real_github.status_code == 200
    assert real_github.security_audit.grade in ("A", "B")
    assert real_github.security_audit.score >= 80



