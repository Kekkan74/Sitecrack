"""
Generador de Informes Ejecutivos de Auditoría Web (report_generator.py).

Diseño SOLID:
- SRP: Se responsabiliza únicamente de transformar las métricas y registros de
  flujos HTTP/S en un informe ejecutivo HTML autocontenido (listo para imprimir
  a PDF o adjuntar en auditorías).
- Seguridad (XSS Safe): Escapa todas las cadenas dinámicas mediante `html.escape`.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import List

from src.domain.schemas import HttpFlowRecord, TrafficStats


def generate_html_audit_report(
    flows: List[HttpFlowRecord],
    stats: TrafficStats,
) -> str:
    """Genera un documento HTML5 ejecutivo autocontenido con diseño Glass moderno."""
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    avg_score = (
        round(sum(f.security_audit.score for f in flows) / len(flows), 1)
        if flows
        else 100.0
    )

    rows_html: List[str] = []
    for f in flows:
        grade = f.security_audit.grade
        tone = (
            "safe"
            if grade in ("A", "B")
            else ("warn" if grade in ("C", "D") else "danger")
        )
        missing_str = (
            ", ".join(f.security_audit.missing_headers)
            if f.security_audit.missing_headers
            else "Ninguno (Todos los escudos activos)"
        )
        findings_items = "".join(
            f"<li><strong>[{html.escape(fd.severity)}] {html.escape(fd.header)}:</strong> {html.escape(fd.description)}</li>"
            for fd in f.security_audit.findings
        )
        if not findings_items:
            findings_items = "<li>✔ Sin vulnerabilidades pasivas detectadas en cabeceras.</li>"

        rows_html.append(
            f"""
            <article class="flow-card border-{tone}">
              <div class="flow-card-header">
                <div>
                  <span class="method-badge">{html.escape(f.method)}</span>
                  <strong class="url-text">{html.escape(f.url)}</strong>
                </div>
                <div class="badges-right">
                  <span class="pill pill-{tone}">Nota {html.escape(grade)} ({f.security_audit.score}/100)</span>
                  <span class="pill">HTTP {f.status_code} · {f.duration_ms:.1f} ms</span>
                </div>
              </div>
              <p class="missing-line"><strong>Escudos ausentes:</strong> {html.escape(missing_str)}</p>
              <ul class="findings-ul">{findings_items}</ul>
            </article>
            """
        )

    body_cards = (
        "\n".join(rows_html)
        if rows_html
        else "<p>No hay peticiones registradas en la sesión actual.</p>"
    )

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Informe de Auditoría Pasiva Web — Sitecrack</title>
  <style>
    body {{
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      background: #F1F5F9;
      color: #0F172A;
      margin: 0;
      padding: 2.5rem 1.5rem;
      line-height: 1.55;
    }}
    .report-container {{
      max-width: 1060px;
      margin: 0 auto;
      background: #FFFFFF;
      border-radius: 16px;
      padding: 2.25rem;
      box-shadow: 0 12px 32px rgba(15, 23, 42, 0.08);
      border: 1px solid #E2E8F0;
    }}
    .report-header {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      border-bottom: 2px solid #E2E8F0;
      padding-bottom: 1.25rem;
      margin-bottom: 1.5rem;
      flex-wrap: wrap;
      gap: 1rem;
    }}
    h1 {{
      margin: 0;
      font-size: 1.5rem;
      color: #0F172A;
    }}
    .meta {{
      font-size: 0.88rem;
      color: #64748B;
      margin-top: 0.25rem;
    }}
    .print-btn {{
      background: #4F46E5;
      color: #FFFFFF;
      border: none;
      border-radius: 8px;
      padding: 0.6rem 1.1rem;
      font-weight: 700;
      cursor: pointer;
    }}
    @media print {{
      .print-btn {{ display: none; }}
      body {{ background: #FFFFFF; padding: 0; }}
      .report-container {{ box-shadow: none; border: none; }}
    }}
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }}
    .kpi-box {{
      padding: 1rem 1.2rem;
      border-radius: 12px;
      background: #F8FAFC;
      border: 1px solid #E2E8F0;
    }}
    .kpi-label {{
      font-size: 0.8rem;
      font-weight: 700;
      color: #64748B;
      text-transform: uppercase;
    }}
    .kpi-val {{
      font-size: 1.6rem;
      font-weight: 800;
      margin-top: 0.2rem;
    }}
    .flow-card {{
      border: 1px solid #E2E8F0;
      border-left-width: 6px;
      border-radius: 12px;
      padding: 1.1rem 1.3rem;
      margin-bottom: 1rem;
      background: #FFFFFF;
    }}
    .border-safe {{ border-left-color: #10B981; }}
    .border-warn {{ border-left-color: #F59E0B; }}
    .border-danger {{ border-left-color: #F43F5E; }}
    .flow-card-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 0.75rem;
      flex-wrap: wrap;
    }}
    .method-badge {{
      font-family: Consolas, monospace;
      font-weight: 700;
      font-size: 0.8rem;
      background: #E0F2FE;
      color: #0369A1;
      padding: 0.2rem 0.5rem;
      border-radius: 5px;
      margin-right: 0.4rem;
    }}
    .url-text {{
      font-family: Consolas, monospace;
      font-size: 0.92rem;
      word-break: break-all;
    }}
    .pill {{
      display: inline-block;
      padding: 0.2rem 0.65rem;
      border-radius: 999px;
      font-size: 0.78rem;
      font-weight: 700;
      background: #F1F5F9;
      color: #334155;
    }}
    .pill-safe {{ background: #DCFCE7; color: #065F46; }}
    .pill-warn {{ background: #FEF3C7; color: #92400E; }}
    .pill-danger {{ background: #FFE4E6; color: #9F1239; }}
    .missing-line {{
      font-size: 0.86rem;
      color: #475569;
      margin: 0.65rem 0 0.4rem 0;
    }}
    .findings-ul {{
      margin: 0;
      padding-left: 1.2rem;
      font-size: 0.85rem;
      color: #334155;
    }}
    .findings-ul li {{ margin-bottom: 0.25rem; }}
  </style>
</head>
<body>
  <div class="report-container">
    <header class="report-header">
      <div>
        <h1>🛡️ Informe Ejecutivo de Auditoría Web — Sitecrack</h1>
        <p class="meta">Generado automáticamente el {generated_at} · Evaluación Pasiva OWASP Secure Headers</p>
      </div>
      <button class="print-btn" onclick="window.print()">🖨️ Imprimir / Guardar en PDF</button>
    </header>

    <section class="kpi-grid">
      <div class="kpi-box">
        <div class="kpi-label">Peticiones Auditadas</div>
        <div class="kpi-val">{stats.total_flows}</div>
      </div>
      <div class="kpi-box">
        <div class="kpi-label">Puntuación Media</div>
        <div class="kpi-val">{avg_score} / 100</div>
      </div>
      <div class="kpi-box">
        <div class="kpi-label">Tráfico Cifrado (HTTPS)</div>
        <div class="kpi-val" style="color:#059669;">{stats.https_count}</div>
      </div>
      <div class="kpi-box">
        <div class="kpi-label">Con Riesgo Alto (D/F)</div>
        <div class="kpi-val" style="color:#E11D48;">{stats.low_security_count}</div>
      </div>
    </section>

    <h2 style="font-size:1.15rem; margin-bottom:1rem;">Desglose Detallado por Petición</h2>
    {body_cards}
  </div>
</body>
</html>
"""
