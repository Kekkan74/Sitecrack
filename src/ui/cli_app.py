"""
Frontend en Consola / TUI Accesible (Textual + Rich) - cli_app.py

Diseño SOLID y Accesibilidad Visual (WCAG AA/AAA & Daltonismo):
- SRP: Se encarga exclusivamente de la representación visual y navegación por teclado,
  delegando toda comunicación HTTP a `TelemetryClientProtocol` (`src/ui/api_client.py`).
- Accesibilidad Cognitiva y Visual:
  1. Cero dependencia exclusiva del color: cada estado HTTP, protocolo y calificación de
     seguridad incluye iconos geométricos redundantes y etiquetas textuales explícitas
     (`✔ 200 OK`, `⚠ 403 CLIENT`, `✖ 500 SERVER`, `🔒 HTTPS`, `🔓 HTTP`, `[★ A]`, `[✖ F]`).
  2. Paleta de alto contraste apta para deuteranopía/protanopía/tritanopía (Cian, Ámbar,
     Magenta Coral y Blanco Puro sobre fondo #0B0F19).
  3. Conmutador instantáneo de Modo Ultra-Contraste Monocromático (tecla `H`) para
     lectores de pantalla o monitores de bajo brillo.
  4. Navegación 100% por teclado con indicadores de foco explícitos.

Ejecución:
    python -m src.ui.cli_app            # TUI conectada a FastAPI (con fallback automático)
    python -m src.ui.cli_app --demo     # TUI con flujos de demostración pre-cargados
    python -m src.ui.cli_app --snapshot # Salida accesible Rich directa en terminal estándar
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.domain.schemas import HttpFlowRecord, TrafficStats
from src.ui.api_client import (
    DemoTelemetryClient,
    FastApiTelemetryClient,
    TelemetryClientProtocol,
)

try:
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal
    from textual.reactive import reactive
    from textual.widgets import DataTable, Footer, Header, Input, RichLog, Static

    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False


# ==============================================================================
# Formateadores Visuales Accesibles (Iconografía + Etiqueta + Color Semántico)
# ==============================================================================


def format_status_badge(status_code: int, high_contrast: bool = False) -> Text:
    """Devuelve etiqueta accesible con símbolo geométrico + código + categoría."""
    if 200 <= status_code < 300:
        label = f"✔ {status_code} OK"
        style = "bold white on black" if high_contrast else "bold #00F5D4"
    elif 300 <= status_code < 400:
        label = f"↪ {status_code} REDIR"
        style = "bold white on black" if high_contrast else "bold #38BDF8"
    elif 400 <= status_code < 500:
        label = f"⚠ {status_code} CLIENT"
        style = "bold reverse" if high_contrast else "bold #FBBF24"
    else:
        label = f"✖ {status_code} SERVER"
        style = "bold underline reverse" if high_contrast else "bold #FB7185"
    return Text(label, style=style)


def format_scheme_badge(scheme: str, high_contrast: bool = False) -> Text:
    """Distingue visualmente tráfico cifrado (TLS) de texto claro."""
    if scheme.lower() == "https":
        style = "bold white" if high_contrast else "bold #34D399"
        return Text("🔒 HTTPS", style=style)
    style = "bold reverse" if high_contrast else "bold #F87171"
    return Text("🔓 HTTP ", style=style)


def format_grade_badge(grade: str, score: int, high_contrast: bool = False) -> Text:
    """Representación accesible de calificación de seguridad pasiva."""
    symbols = {"A": "★", "B": "◆", "C": "▲", "D": "▼", "F": "✖"}
    colors = {
        "A": "bold #00F5D4",
        "B": "bold #38BDF8",
        "C": "bold #FBBF24",
        "D": "bold #FB923C",
        "F": "bold #FB7185",
    }
    sym = symbols.get(grade, "•")
    style = "bold white" if high_contrast else colors.get(grade, "bold white")
    return Text(f"[{sym} {grade} | {score:>3}]", style=style)


def build_inspector_renderable(
    flow: HttpFlowRecord, high_contrast: bool = False
) -> Panel:
    """Construye el informe detallado del flujo seleccionado para el panel derecho."""
    body = Text()
    accent = "bold white" if high_contrast else "bold #38BDF8"
    warn_style = "bold underline white" if high_contrast else "bold #FB7185"
    ok_style = "bold white" if high_contrast else "bold #00F5D4"

    body.append("■ METADATOS DE TRANSACCIÓN\n", style=accent)
    body.append(f"  ID Flujo   : #{flow.id}\n")
    body.append(f"  Timestamp  : {flow.timestamp}\n")
    body.append(f"  Endpoint   : {flow.method} {flow.url}\n")
    body.append(
        f"  Estado     : {flow.status_code} | Latencia: {flow.duration_ms} ms\n"
    )
    body.append(
        f"  Tamaños    : Req {flow.request_size} B / Resp {flow.response_size} B ({flow.content_type})\n\n"
    )

    audit = flow.security_audit
    body.append(
        f"■ AUDITORÍA PASIVA DE SEGURIDAD (Calificación: {audit.grade} - {audit.score}/100)\n",
        style=accent,
    )
    if not audit.findings:
        body.append(
            "  ✔ Todas las cabeceras defensivas OWASP están presentes.\n\n",
            style=ok_style,
        )
    else:
        for finding in audit.findings:
            sev_icon = (
                "✖"
                if finding.severity == "HIGH"
                else ("⚠" if finding.severity == "MEDIUM" else "ℹ")
            )
            st = (
                warn_style
                if finding.severity in ("HIGH", "MEDIUM")
                else "bold #FBBF24"
            )
            body.append(
                f"  {sev_icon} [{finding.severity}] {finding.header}: ",
                style=st,
            )
            body.append(f"{finding.description}\n")
        body.append("\n")

    body.append("■ CABECERAS DE PETICIÓN (Sanitizadas CWE-532)\n", style=accent)
    for k, v in flow.request_headers.items():
        body.append(f"  {k}: ", style="bold")
        body.append(f"{v}\n")
    body.append("\n")

    body.append("■ CABECERAS DE RESPUESTA\n", style=accent)
    for k, v in flow.response_headers.items():
        body.append(f"  {k}: ", style="bold")
        body.append(f"{v}\n")
    body.append("\n")

    if flow.request_preview:
        body.append("■ VISTA PREVIA PAYLOAD PETICIÓN (<= 2KB)\n", style=accent)
        body.append(f"  {flow.request_preview}\n\n")

    if flow.response_preview:
        body.append("■ VISTA PREVIA PAYLOAD RESPUESTA (<= 2KB)\n", style=accent)
        body.append(f"  {flow.response_preview}\n")

    border = "white" if high_contrast else "#38BDF8"
    return Panel(
        body,
        title=f"[bold]Inspector Forense de Flujo #{flow.id} ({flow.host})[/bold]",
        border_style=border,
    )


def render_cli_snapshot(
    use_demo: bool = False, high_contrast: bool = False
) -> None:
    """
    Modo de impresión estática accesible con `Rich` (para lectores de pantalla,
    terminales sin soporte de buffer alternativo o validación rápida).
    """
    console = Console()
    client: TelemetryClientProtocol = (
        DemoTelemetryClient() if use_demo else FastApiTelemetryClient()
    )
    try:
        flows = client.fetch_flows(limit=25)
        stats = client.fetch_stats()
        source_label = "FASTAPI LIVE" if not use_demo else "DEMO DATA"
    except Exception:
        demo = DemoTelemetryClient()
        flows = demo.fetch_flows(limit=25)
        stats = demo.fetch_stats()
        source_label = "DEMO DATA (Fallback Offline)"

    table = Table(
        title=f"🛡️ SITECRACK // Resumen Accesible de Tráfico Interceptado [{source_label}]",
        caption=(
            f"Total: {stats.total_flows} | HTTPS: {stats.https_count} | "
            f"HTTP: {stats.http_count} | Errores: {stats.error_count} | "
            f"Riesgo Alto (D/F): {stats.low_security_count}"
        ),
        show_lines=True,
    )
    table.add_column("ID", justify="right", style="bold")
    table.add_column("Protocolo", justify="center")
    table.add_column("Método", justify="center", style="bold")
    table.add_column("Estado", justify="left")
    table.add_column("Endpoint (Host + Ruta)", justify="left")
    table.add_column("Latencia", justify="right")
    table.add_column("Auditoría Pasiva", justify="center")

    for f in flows:
        table.add_row(
            f"#{f.id}",
            format_scheme_badge(f.scheme, high_contrast),
            f.method,
            format_status_badge(f.status_code, high_contrast),
            f"{f.host}{f.path}",
            f"{f.duration_ms:.1f} ms",
            format_grade_badge(
                f.security_audit.grade, f.security_audit.score, high_contrast
            ),
        )

    console.print(table)
    if flows:
        console.print(build_inspector_renderable(flows[0], high_contrast))


# ==============================================================================
# Aplicación TUI Interactiva (Textual)
# ==============================================================================

if TEXTUAL_AVAILABLE:

    class SitecrackTUIApp(App[None]):
        """Interfaz de Terminal (TUI) de bajo consumo y alta accesibilidad visual."""

        TITLE = "SITECRACK // HTTP/S Intercept & Passive Security Auditor"
        SUB_TITLE = "SOLID Architecture • Accessible High-Contrast TUI"

        CSS = """
        Screen {
            background: #0B0F19;
            color: #F8FAFC;
        }

        Screen.high-contrast {
            background: #000000;
            color: #FFFFFF;
        }

        #kpi-banner {
            height: 3;
            padding: 0 2;
            background: #111827;
            border: tall #1E293B;
            content-align: left middle;
            text-style: bold;
        }

        Screen.high-contrast #kpi-banner {
            background: #000000;
            border: double #FFFFFF;
        }

        #filter-bar {
            height: 3;
            margin: 0 0 1 0;
        }

        #workspace {
            height: 1fr;
        }

        #flows-table {
            width: 58%;
            height: 1fr;
            border: round #38BDF8;
            background: #0F172A;
        }

        Screen.high-contrast #flows-table {
            border: heavy #FFFFFF;
            background: #000000;
        }

        #flows-table:focus {
            border: double #00F5D4;
        }

        #inspector-pane {
            width: 42%;
            height: 1fr;
            border: round #64748B;
            background: #0F172A;
            padding: 0 1;
        }

        Screen.high-contrast #inspector-pane {
            border: heavy #FFFFFF;
            background: #000000;
        }
        """

        BINDINGS = [
            Binding("r", "refresh_flows", "Refrescar (R)", show=True),
            Binding("f", "focus_filter", "Filtrar Host (F)", show=True),
            Binding("h", "toggle_contrast", "Alto Contraste WCAG (H)", show=True),
            Binding("d", "toggle_demo", "Modo Demo/Live (D)", show=True),
            Binding("x", "clear_history", "Limpiar (X)", show=True),
            Binding("q", "quit", "Salir (Q)", show=True),
        ]

        high_contrast: reactive[bool] = reactive(False)
        using_demo: reactive[bool] = reactive(False)

        def __init__(
            self,
            live_client: Optional[TelemetryClientProtocol] = None,
            start_in_demo: bool = False,
        ) -> None:
            super().__init__()
            self._live_client: TelemetryClientProtocol = (
                live_client or FastApiTelemetryClient()
            )
            self._demo_client: TelemetryClientProtocol = DemoTelemetryClient()
            self.using_demo = start_in_demo
            self._records_by_id: Dict[int, HttpFlowRecord] = {}
            self._current_filter: str = ""

        @property
        def active_client(self) -> TelemetryClientProtocol:
            return self._demo_client if self.using_demo else self._live_client

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            yield Static("Cargando telemetría...", id="kpi-banner")
            yield Input(
                placeholder="🔍 Filtrar por dominio/host (presiona Enter para aplicar, Esc para volver a la tabla)...",
                id="filter-bar",
            )
            with Horizontal(id="workspace"):
                yield DataTable(id="flows-table", cursor_type="row", zebra_stripes=True)
                yield RichLog(
                    id="inspector-pane", highlight=True, markup=True, wrap=True
                )
            yield Footer()

        def on_mount(self) -> None:
            table = self.query_one("#flows-table", DataTable)
            table.add_columns(
                "ID",
                "Proto",
                "Método",
                "Estado HTTP",
                "Host / Ruta",
                "Latencia",
                "Postura Sec",
            )
            self._reload_data()
            self.set_interval(3.0, self._reload_data)
            table.focus()

        def _reload_data(self) -> None:
            try:
                flows = self.active_client.fetch_flows(
                    limit=100,
                    host_filter=self._current_filter or None,
                )
                stats = self.active_client.fetch_stats()
                mode_tag = (
                    "🧪 MODO DEMO" if self.using_demo else "🟢 CONECTADO A FASTAPI"
                )
            except Exception:
                flows = self._demo_client.fetch_flows(
                    limit=100,
                    host_filter=self._current_filter or None,
                )
                stats = self._demo_client.fetch_stats()
                mode_tag = "⚠️ OFFLINE (Mostrando Demo Interactiva)"

            self._update_banner(stats, mode_tag)
            self._populate_table(flows)

        def _update_banner(self, stats: TrafficStats, mode_tag: str) -> None:
            banner = self.query_one("#kpi-banner", Static)
            contrast_tag = (
                "♿ WCAG AAA: ON" if self.high_contrast else "🎨 TEMA: SOC DARK"
            )
            summary = (
                f"{mode_tag}  │  📊 Flujos: {stats.total_flows}  │  "
                f"🔒 HTTPS: {stats.https_count} / 🔓 HTTP: {stats.http_count}  │  "
                f"✖ Errores (4xx/5xx): {stats.error_count}  │  "
                f"⚠ Riesgo Sec (D/F): {stats.low_security_count}  │  "
                f"⏱ Media: {stats.avg_duration_ms} ms  │  {contrast_tag}"
            )
            banner.update(summary)

        def _populate_table(self, flows: List[HttpFlowRecord]) -> None:
            table = self.query_one("#flows-table", DataTable)
            selected_row = table.cursor_row
            table.clear()
            self._records_by_id.clear()

            for flow in flows:
                self._records_by_id[flow.id] = flow
                endpoint_label = f"{flow.host}{flow.path}"
                if len(endpoint_label) > 40:
                    endpoint_label = endpoint_label[:37] + "..."

                table.add_row(
                    f"#{flow.id}",
                    format_scheme_badge(flow.scheme, self.high_contrast),
                    Text(flow.method, style="bold"),
                    format_status_badge(flow.status_code, self.high_contrast),
                    endpoint_label,
                    f"{flow.duration_ms:>6.1f} ms",
                    format_grade_badge(
                        flow.security_audit.grade,
                        flow.security_audit.score,
                        self.high_contrast,
                    ),
                    key=str(flow.id),
                )

            if flows:
                target_row = min(max(0, selected_row), len(flows) - 1)
                table.move_cursor(row=target_row)
                chosen_flow = flows[target_row]
                self._render_inspector(chosen_flow)

        def _render_inspector(self, flow: HttpFlowRecord) -> None:
            inspector = self.query_one("#inspector-pane", RichLog)
            inspector.clear()
            inspector.write(build_inspector_renderable(flow, self.high_contrast))

        def on_data_table_row_highlighted(
            self, event: DataTable.RowHighlighted
        ) -> None:
            if event.row_key and event.row_key.value:
                flow_id = int(event.row_key.value)
                flow = self._records_by_id.get(flow_id)
                if flow is not None:
                    self._render_inspector(flow)

        def on_input_submitted(self, event: Input.Submitted) -> None:
            self._current_filter = event.value.strip()
            self._reload_data()
            self.query_one("#flows-table", DataTable).focus()

        def action_refresh_flows(self) -> None:
            self._reload_data()

        def action_focus_filter(self) -> None:
            self.query_one("#filter-bar", Input).focus()

        def action_toggle_contrast(self) -> None:
            self.high_contrast = not self.high_contrast
            self.screen.set_class(self.high_contrast, "high-contrast")
            self._reload_data()

        def action_toggle_demo(self) -> None:
            self.using_demo = not self.using_demo
            self._reload_data()

        def action_clear_history(self) -> None:
            try:
                self.active_client.clear_all()
            except Exception:
                pass
            self._reload_data()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sitecrack Accessible Terminal UI (Textual / Rich)"
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Inicia con telemetría de demostración pre-cargada.",
    )
    parser.add_argument(
        "--snapshot",
        action="store_true",
        help="Imprime tabla e inspector Rich en consola estándar y termina.",
    )
    parser.add_argument(
        "--high-contrast",
        action="store_true",
        help="Activa modo monocromático WCAG AAA de alto contraste.",
    )
    args = parser.parse_args()

    if args.snapshot or not TEXTUAL_AVAILABLE:
        render_cli_snapshot(
            use_demo=args.demo, high_contrast=args.high_contrast
        )
    else:
        app = SitecrackTUIApp(start_in_demo=args.demo)
        app.high_contrast = args.high_contrast
        app.run()


if __name__ == "__main__":
    main()
