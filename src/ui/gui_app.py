"""
Aplicación Gráfica de Escritorio Nativa (Tkinter / TTK) - gui_app.py

Cumple con los principios SOLID:
- SRP: Se encarga únicamente de la ventana gráfica nativa de escritorio.
- DIP: Consume `TelemetryClientProtocol` (`FastApiTelemetryClient` o `DemoTelemetryClient`),
  demostrando cómo el bajo acoplamiento permite cambiar la interfaz de terminal por
  una aplicación gráfica de escritorio sin modificar ni una línea del backend ni del proxy.

Ejecución:
    python -m src.ui.gui_app
"""

from __future__ import annotations

import sys
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk
from typing import Dict, List, Optional
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.api.api_server import get_repository
from src.core.security_analyzer import PassiveSecurityAnalyzer, sanitize_headers
from src.domain.schemas import HttpFlowCreate, HttpFlowRecord
from src.ui.api_client import DemoTelemetryClient


HEADER_EXPLANATIONS: Dict[str, str] = {
    "Strict-Transport-Security": "Fuerza conexiones cifradas HTTPS evitando ataques de downgrade.",
    "Content-Security-Policy": "Restringe orígenes de scripts previniendo inyección XSS.",
    "X-Content-Type-Options": "Impide que el navegador ejecute archivos disfrazados (nosniff).",
    "X-Frame-Options": "Protege contra Clickjacking impidiendo incrustar la web en iframes.",
    "Referrer-Policy": "Evita filtrar URLs sensibles en la cabecera Referer.",
    "Permissions-Policy": "Bloquea acceso no autorizado a cámara, micrófono o GPS.",
}


class SitecrackDesktopGUI:
    """Ventana gráfica de escritorio intuitiva y accesible para Sitecrack."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Sitecrack App — Inspector Gráfico HTTP/S y Auditor de Seguridad")
        self.root.geometry("1280x780")
        self.root.minsize(980, 620)

        self.repo = get_repository()
        self.high_contrast = False
        self.flows_by_id: Dict[int, HttpFlowRecord] = {}

        # Sembrar datos iniciales si la base de datos está vacía para que la app sea intuitiva al abrir
        if len(self.repo.list_flows(limit=5)) == 0:
            self._seed_demo_data()

        self._setup_styles()
        self._build_layout()
        self.refresh_data()

    def _setup_styles(self) -> None:
        self.style = ttk.Style(self.root)
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass
        self._apply_palette()

    def _apply_palette(self) -> None:
        if self.high_contrast:
            bg_main = "#060911"
            bg_panel = "#0F172A"
            fg_main = "#FFFFFF"
            accent = "#38BDF8"
            sel_bg = "#0284C7"
        else:
            bg_main = "#F1F5F9"
            bg_panel = "#FFFFFF"
            fg_main = "#0F172A"
            accent = "#0284C7"
            sel_bg = "#0284C7"

        self.root.configure(bg=bg_main)
        self.style.configure("TFrame", background=bg_main)
        self.style.configure("Card.TFrame", background=bg_panel)
        self.style.configure(
            "TLabel", background=bg_main, foreground=fg_main, font=("Segoe UI", 10)
        )
        self.style.configure(
            "Header.TLabel",
            background=bg_panel,
            foreground=fg_main,
            font=("Segoe UI", 14, "bold"),
        )
        self.style.configure(
            "SubHeader.TLabel",
            background=bg_panel,
            foreground=fg_main,
            font=("Segoe UI", 10),
        )
        self.style.configure(
            "KPI.TLabel",
            background=bg_panel,
            foreground=accent,
            font=("Consolas", 12, "bold"),
        )
        self.style.configure(
            "Treeview",
            background=bg_panel,
            fieldbackground=bg_panel,
            foreground=fg_main,
            rowheight=30,
            font=("Segoe UI", 10),
        )
        self.style.configure(
            "Treeview.Heading",
            font=("Segoe UI", 10, "bold"),
            padding=6,
        )
        self.style.map(
            "Treeview",
            background=[("selected", sel_bg)],
            foreground=[("selected", "#FFFFFF")],
        )

    def _build_layout(self) -> None:
        # Barra superior
        topbar = ttk.Frame(self.root, style="Card.TFrame", padding=(16, 12))
        topbar.pack(fill=tk.X, side=tk.TOP)

        title_box = ttk.Frame(topbar, style="Card.TFrame")
        title_box.pack(side=tk.LEFT)
        ttk.Label(
            title_box,
            text="🛡️ Sitecrack App",
            style="Header.TLabel",
        ).pack(anchor=tk.W)
        ttk.Label(
            title_box,
            text="Inspector visual de tráfico HTTP/S y diagnóstico pasivo de seguridad",
            style="SubHeader.TLabel",
        ).pack(anchor=tk.W)

        btn_box = ttk.Frame(topbar, style="Card.TFrame")
        btn_box.pack(side=tk.RIGHT)

        ttk.Button(
            btn_box,
            text="＋ Cargar tráfico de muestra",
            command=self.action_seed_demo,
        ).pack(side=tk.LEFT, padx=4)
        ttk.Button(
            btn_box,
            text="⚡ Simular petición",
            command=self.action_open_simulator,
        ).pack(side=tk.LEFT, padx=4)
        ttk.Button(
            btn_box,
            text="↻ Actualizar",
            command=self.refresh_data,
        ).pack(side=tk.LEFT, padx=4)
        ttk.Button(
            btn_box,
            text="♿ Alto Contraste",
            command=self.action_toggle_contrast,
        ).pack(side=tk.LEFT, padx=4)
        ttk.Button(
            btn_box,
            text="🗑 Limpiar historial",
            command=self.action_clear,
        ).pack(side=tk.LEFT, padx=4)

        # Cinta de métricas
        kpi_frame = ttk.Frame(self.root, padding=(16, 8))
        kpi_frame.pack(fill=tk.X)
        self.kpi_var = tk.StringVar(value="Cargando métricas...")
        ttk.Label(kpi_frame, textvariable=self.kpi_var, style="KPI.TLabel").pack(
            fill=tk.X
        )

        # Barra de búsqueda
        filter_frame = ttk.Frame(self.root, padding=(16, 4))
        filter_frame.pack(fill=tk.X)
        ttk.Label(filter_frame, text="🔍 Filtrar por dominio:").pack(
            side=tk.LEFT, padx=(0, 8)
        )
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self.refresh_data())
        search_entry = ttk.Entry(
            filter_frame, textvariable=self.search_var, width=40, font=("Segoe UI", 10)
        )
        search_entry.pack(side=tk.LEFT, padx=(0, 12))

        # Paneles divididos (Izquierda: Tabla / Derecha: Inspector con pestañas)
        paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=16, pady=(4, 16))

        left_frame = ttk.Frame(paned)
        right_frame = ttk.Frame(paned)
        paned.add(left_frame, weight=5)
        paned.add(right_frame, weight=5)

        columns = ("id", "proto", "method", "host", "status", "latency", "grade")
        self.tree = ttk.Treeview(
            left_frame, columns=columns, show="headings", selectmode="browse"
        )
        self.tree.heading("id", text="#")
        self.tree.heading("proto", text="Red")
        self.tree.heading("method", text="Método")
        self.tree.heading("host", text="Dominio y Ruta")
        self.tree.heading("status", text="Respuesta")
        self.tree.heading("latency", text="Tiempo")
        self.tree.heading("grade", text="Nota Seguridad")

        self.tree.column("id", width=45, anchor=tk.CENTER)
        self.tree.column("proto", width=85, anchor=tk.CENTER)
        self.tree.column("method", width=70, anchor=tk.CENTER)
        self.tree.column("host", width=230, anchor=tk.W)
        self.tree.column("status", width=110, anchor=tk.CENTER)
        self.tree.column("latency", width=80, anchor=tk.E)
        self.tree.column("grade", width=120, anchor=tk.CENTER)

        scrollbar = ttk.Scrollbar(
            left_frame, orient=tk.VERTICAL, command=self.tree.yview
        )
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<<TreeviewSelect>>", self.on_row_selected)

        # Notebook (Pestañas de inspección visual)
        self.notebook = ttk.Notebook(right_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.txt_security = tk.Text(
            self.notebook,
            wrap=tk.WORD,
            font=("Consolas", 10),
            padx=12,
            pady=12,
        )
        self.txt_headers = tk.Text(
            self.notebook,
            wrap=tk.WORD,
            font=("Consolas", 10),
            padx=12,
            pady=12,
        )
        self.txt_payload = tk.Text(
            self.notebook,
            wrap=tk.WORD,
            font=("Consolas", 10),
            padx=12,
            pady=12,
        )

        self.notebook.add(self.txt_security, text=" 🛡️ Diagnóstico de Seguridad ")
        self.notebook.add(self.txt_headers, text=" 📋 Cabeceras (Headers) ")
        self.notebook.add(self.txt_payload, text=" 📦 Datos Enviados/Recibidos ")

    def _seed_demo_data(self) -> None:
        demo_records = DemoTelemetryClient().fetch_flows(limit=10)
        for item in reversed(demo_records):
            dto = HttpFlowCreate(**item.model_dump(exclude={"id"}))
            self.repo.save_flow(dto)

    def refresh_data(self) -> None:
        host_filter = self.search_var.get().strip() or None
        flows = self.repo.list_flows(limit=150, host_filter=host_filter)
        stats = self.repo.get_stats()

        self.kpi_var.set(
            f"📊 Total: {stats.total_flows} peticiones   │   "
            f"🔒 Cifradas (HTTPS): {stats.https_count}   │   "
            f"🔓 Sin cifrar (HTTP): {stats.http_count}   │   "
            f"⚠ Con Alerta de Seguridad (D/F): {stats.low_security_count}   │   "
            f"⏱ Tiempo medio: {stats.avg_duration_ms} ms"
        )

        for item in self.tree.get_children():
            self.tree.delete(item)
        self.flows_by_id.clear()

        for f in flows:
            self.flows_by_id[f.id] = f
            proto_lbl = "🔒 HTTPS" if f.scheme.lower() == "https" else "🔓 HTTP"
            if 200 <= f.status_code < 300:
                status_lbl = f"✔ {f.status_code} OK"
            elif 400 <= f.status_code < 500:
                status_lbl = f"⚠ {f.status_code} Aviso"
            else:
                status_lbl = f"✖ {f.status_code} Error"

            grade_lbl = f"Nota {f.security_audit.grade} ({f.security_audit.score}/100)"
            self.tree.insert(
                "",
                tk.END,
                iid=str(f.id),
                values=(
                    f"#{f.id}",
                    proto_lbl,
                    f.method,
                    f"{f.host}{f.path}",
                    status_lbl,
                    f"{f.duration_ms:.1f} ms",
                    grade_lbl,
                ),
            )

        children = self.tree.get_children()
        if children:
            self.tree.selection_set(children[0])
            self.tree.focus(children[0])
            self._render_flow_details(flows[0])
        else:
            self._clear_inspector()

    def _clear_inspector(self) -> None:
        for widget in (self.txt_security, self.txt_headers, self.txt_payload):
            widget.configure(state=tk.NORMAL)
            widget.delete("1.0", tk.END)
            widget.insert(
                tk.END,
                "No hay peticiones seleccionadas. Pulsa '＋ Cargar tráfico de muestra' para explorar ejemplos.",
            )
            widget.configure(state=tk.DISABLED)

    def on_row_selected(self, _event: object) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        flow_id = int(sel[0])
        flow = self.flows_by_id.get(flow_id)
        if flow:
            self._render_flow_details(flow)

    def _render_flow_details(self, flow: HttpFlowRecord) -> None:
        audit = flow.security_audit

        # 1. Pestaña de Seguridad explicada en lenguaje claro
        sec_lines = [
            f"PETICIÓN SELECCIONADA: #{flow.id} [{flow.method}] {flow.url}",
            f"CALIFICACIÓN DE SEGURIDAD: Nota {audit.grade} ({audit.score} / 100 puntos)",
            "=" * 76,
            "",
            "1. HALLAZGOS DETECTADOS EN ESTA RESPUESTA:",
        ]
        if not audit.findings:
            sec_lines.append(
                "   ✔ Excelente: Todas las cabeceras de protección web recomendadas están activas."
            )
        else:
            for finding in audit.findings:
                icon = "✖" if finding.severity == "HIGH" else "⚠"
                sec_lines.append(
                    f"   {icon} [{finding.severity}] {finding.header}: {finding.description}"
                )

        sec_lines.extend(
            [
                "",
                "2. LISTA DE COMPROBACIÓN DE PROTECCIONES WEB (¿Qué significa cada una?):",
                "-" * 76,
            ]
        )
        for h_name, explanation in HEADER_EXPLANATIONS.items():
            status_tag = (
                "✖ FALTA" if h_name in audit.missing_headers else "✔ PRESENTE"
            )
            sec_lines.append(f"• {h_name:<28} -> [{status_tag}]")
            sec_lines.append(f"  Explicación: {explanation}\n")

        self._set_text(self.txt_security, "\n".join(sec_lines))

        # 2. Pestaña de Cabeceras
        hdr_lines = [
            "📤 CABECERAS ENVIADAS POR EL CLIENTE (Credenciales ocultadas CWE-532):",
            "=" * 76,
        ]
        for k, v in flow.request_headers.items():
            hdr_lines.append(f"  {k}: {v}")

        hdr_lines.extend(
            [
                "",
                "📥 CABECERAS DEVUELTAS POR EL SERVIDOR:",
                "=" * 76,
            ]
        )
        for k, v in flow.response_headers.items():
            hdr_lines.append(f"  {k}: {v}")

        self._set_text(self.txt_headers, "\n".join(hdr_lines))

        # 3. Pestaña de Datos (Payloads)
        pay_lines = [
            f"📤 CUERPO ENVIADO EN LA PETICIÓN ({flow.request_size} bytes):",
            "=" * 76,
            flow.request_preview or "(Sin cuerpo en la petición)",
            "",
            f"📥 CUERPO RECIBIDO EN LA RESPUESTA ({flow.response_size} bytes · {flow.content_type}):",
            "=" * 76,
            flow.response_preview or "(Sin cuerpo textual en la respuesta)",
        ]
        self._set_text(self.txt_payload, "\n".join(pay_lines))

    def _set_text(self, widget: tk.Text, content: str) -> None:
        bg = "#0F172A" if self.high_contrast else "#FFFFFF"
        fg = "#FFFFFF" if self.high_contrast else "#0F172A"
        widget.configure(state=tk.NORMAL, bg=bg, fg=fg, insertbackground=fg)
        widget.delete("1.0", tk.END)
        widget.insert(tk.END, content)
        widget.configure(state=tk.DISABLED)

    def action_seed_demo(self) -> None:
        self._seed_demo_data()
        self.refresh_data()

    def action_clear(self) -> None:
        self.repo.clear_flows()
        self.refresh_data()

    def action_toggle_contrast(self) -> None:
        self.high_contrast = not self.high_contrast
        self._apply_palette()
        self.refresh_data()

    def action_open_simulator(self) -> None:
        win = tk.Toplevel(self.root)
        win.title("⚡ Simular Petición Web")
        win.geometry("460x320")
        win.transient(self.root)
        win.grab_set()

        frame = ttk.Frame(win, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="URL de la petición:").pack(anchor=tk.W)
        url_var = tk.StringVar(value="https://mi-banco.ejemplo.es/api/pagos")
        ttk.Entry(frame, textvariable=url_var, width=50).pack(
            fill=tk.X, pady=(2, 10)
        )

        ttk.Label(frame, text="Método HTTP:").pack(anchor=tk.W)
        method_var = tk.StringVar(value="POST")
        ttk.Combobox(
            frame,
            textvariable=method_var,
            values=("GET", "POST", "PUT", "DELETE"),
            state="readonly",
        ).pack(fill=tk.X, pady=(2, 10))

        ttk.Label(frame, text="Nivel de protección del servidor:").pack(anchor=tk.W)
        preset_var = tk.StringVar(value="hardened")
        ttk.Combobox(
            frame,
            textvariable=preset_var,
            values=("hardened", "partial", "vulnerable"),
            state="readonly",
        ).pack(fill=tk.X, pady=(2, 16))

        def submit() -> None:
            raw_url = url_var.get().strip()
            parsed = urlparse(raw_url if "://" in raw_url else f"https://{raw_url}")
            scheme = (parsed.scheme or "https").lower()
            host = parsed.netloc or "ejemplo.es"
            path = parsed.path or "/"
            preset = preset_var.get()

            if preset == "hardened":
                resp_headers = {
                    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
                    "Content-Security-Policy": "default-src 'self'",
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "Referrer-Policy": "no-referrer",
                    "Permissions-Policy": "geolocation=()",
                }
            elif preset == "partial":
                resp_headers = {
                    "Strict-Transport-Security": "max-age=31536000",
                }
            else:
                resp_headers = {"Server": "Apache/2.4.49"}

            audit = PassiveSecurityAnalyzer().evaluate(scheme, resp_headers)
            dto = HttpFlowCreate(
                method=method_var.get(),
                scheme=scheme,
                host=host,
                path=path,
                url=f"{scheme}://{host}{path}",
                status_code=200,
                content_type="application/json",
                duration_ms=18.5,
                request_size=64,
                response_size=128,
                request_headers=sanitize_headers(
                    {"Host": host, "Authorization": "Bearer secret_token_12345"}
                ),
                response_headers=resp_headers,
                request_preview='{"operacion": "simulada"}',
                response_preview='{"estado": "ok"}',
                security_audit=audit,
            )
            self.repo.save_flow(dto)
            win.destroy()
            self.refresh_data()

        ttk.Button(
            frame, text="Guardar y Analizar Petición", command=submit
        ).pack(anchor=tk.E)


def main() -> None:
    root = tk.Tk()
    SitecrackDesktopGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
