"""
Aplicación Gráfica de Escritorio (Tkinter / TTK Modernizada) - gui_app.py

Diseño limpio, minimalista y con paleta Nordic Alabaster / Obsidian Studio.
"""

from __future__ import annotations

import sys
import tkinter as tk
from pathlib import Path
from tkinter import ttk
from typing import Dict
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.api.api_server import get_repository
from src.core.security_analyzer import PassiveSecurityAnalyzer, sanitize_headers
from src.domain.schemas import HttpFlowCreate, HttpFlowRecord
from src.ui.api_client import DemoTelemetryClient


HEADER_EXPLANATIONS: Dict[str, str] = {
    "Strict-Transport-Security": "Cifrado obligatorio (HSTS): evita que alguien espíe tus datos en redes Wi-Fi.",
    "Content-Security-Policy": "Escudo contra código intruso (CSP): bloquea scripts inyectados por terceros.",
    "X-Content-Type-Options": "Verificación de archivos: impide ejecutar archivos de texto como programas.",
    "X-Frame-Options": "Bloqueo de trampas visuales: evita incrustar la web en marcos invisibles.",
    "Referrer-Policy": "Privacidad de navegación: no filtra la ruta privada al pulsar enlaces externos.",
    "Permissions-Policy": "Control de sensores: restringe el uso de cámara, micrófono y ubicación.",
}


class SitecrackDesktopGUI:
    """Ventana gráfica simplificada y moderna para Sitecrack."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Sitecrack — Inspector Sencillo de Seguridad Web")
        self.root.geometry("1260x760")
        self.root.minsize(960, 600)

        self.repo = get_repository()
        self.dark_mode = False
        self.flows_by_id: Dict[int, HttpFlowRecord] = {}

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
        if self.dark_mode:
            bg_main = "#0B0F17"
            bg_panel = "#131B2E"
            fg_main = "#F8FAFC"
            fg_sub = "#94A3B8"
            accent = "#6366F1"
        else:
            bg_main = "#F8FAFC"
            bg_panel = "#FFFFFF"
            fg_main = "#0F172A"
            fg_sub = "#64748B"
            accent = "#4F46E5"

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
            font=("Segoe UI", 13, "bold"),
        )
        self.style.configure(
            "SubHeader.TLabel",
            background=bg_panel,
            foreground=fg_sub,
            font=("Segoe UI", 9),
        )
        self.style.configure(
            "KPI.TLabel",
            background=bg_main,
            foreground=accent,
            font=("Segoe UI", 10, "bold"),
        )
        self.style.configure(
            "Treeview",
            background=bg_panel,
            fieldbackground=bg_panel,
            foreground=fg_main,
            rowheight=34,
            font=("Segoe UI", 10),
            borderwidth=0,
        )
        self.style.configure(
            "Treeview.Heading",
            font=("Segoe UI", 9, "bold"),
            padding=8,
        )
        self.style.map(
            "Treeview",
            background=[("selected", accent)],
            foreground=[("selected", "#FFFFFF")],
        )

    def _build_layout(self) -> None:
        topbar = ttk.Frame(self.root, style="Card.TFrame", padding=(20, 14))
        topbar.pack(fill=tk.X, side=tk.TOP)

        title_box = ttk.Frame(topbar, style="Card.TFrame")
        title_box.pack(side=tk.LEFT)
        ttk.Label(title_box, text="Sitecrack", style="Header.TLabel").pack(anchor=tk.W)
        ttk.Label(
            title_box,
            text="Inspector sencillo de peticiones y seguridad web",
            style="SubHeader.TLabel",
        ).pack(anchor=tk.W)

        btn_box = ttk.Frame(topbar, style="Card.TFrame")
        btn_box.pack(side=tk.RIGHT)

        ttk.Button(
            btn_box, text="＋ Nueva prueba", command=self.action_open_simulator
        ).pack(side=tk.LEFT, padx=4)
        ttk.Button(
            btn_box, text="Cargar ejemplos", command=self.action_seed_demo
        ).pack(side=tk.LEFT, padx=4)
        ttk.Button(
            btn_box, text="☾ Tema", command=self.action_toggle_theme
        ).pack(side=tk.LEFT, padx=4)
        ttk.Button(
            btn_box, text="Vaciar", command=self.action_clear
        ).pack(side=tk.LEFT, padx=4)

        subbar = ttk.Frame(self.root, padding=(20, 10))
        subbar.pack(fill=tk.X)

        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self.refresh_data())
        ttk.Label(subbar, text="Buscar:").pack(side=tk.LEFT, padx=(0, 6))
        ttk.Entry(
            subbar, textvariable=self.search_var, width=32, font=("Segoe UI", 10)
        ).pack(side=tk.LEFT, padx=(0, 20))

        self.kpi_var = tk.StringVar(value="")
        ttk.Label(subbar, textvariable=self.kpi_var, style="KPI.TLabel").pack(
            side=tk.RIGHT
        )

        paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))

        left_frame = ttk.Frame(paned)
        right_frame = ttk.Frame(paned)
        paned.add(left_frame, weight=4)
        paned.add(right_frame, weight=6)

        columns = ("method", "endpoint", "status", "grade")
        self.tree = ttk.Treeview(
            left_frame, columns=columns, show="headings", selectmode="browse"
        )
        self.tree.heading("method", text="Tipo")
        self.tree.heading("endpoint", text="Web y Ruta")
        self.tree.heading("status", text="Estado")
        self.tree.heading("grade", text="Seguridad")

        self.tree.column("method", width=70, anchor=tk.CENTER)
        self.tree.column("endpoint", width=260, anchor=tk.W)
        self.tree.column("status", width=95, anchor=tk.CENTER)
        self.tree.column("grade", width=120, anchor=tk.CENTER)

        scrollbar = ttk.Scrollbar(
            left_frame, orient=tk.VERTICAL, command=self.tree.yview
        )
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.bind("<<TreeviewSelect>>", self.on_row_selected)

        self.notebook = ttk.Notebook(right_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.txt_security = tk.Text(
            self.notebook, wrap=tk.WORD, font=("Segoe UI", 10), padx=16, pady=16, bd=0
        )
        self.txt_headers = tk.Text(
            self.notebook, wrap=tk.WORD, font=("Consolas", 10), padx=16, pady=16, bd=0
        )
        self.txt_payload = tk.Text(
            self.notebook, wrap=tk.WORD, font=("Consolas", 10), padx=16, pady=16, bd=0
        )

        self.notebook.add(self.txt_security, text=" Escudos de Seguridad ")
        self.notebook.add(self.txt_headers, text=" Cabeceras Técnicas ")
        self.notebook.add(self.txt_payload, text=" Contenido / Datos ")

    def _seed_demo_data(self) -> None:
        demo_records = DemoTelemetryClient().fetch_flows(limit=10)
        for item in reversed(demo_records):
            dto = HttpFlowCreate(**item.model_dump(exclude={"id"}))
            self.repo.save_flow(dto)

    def refresh_data(self) -> None:
        host_filter = self.search_var.get().strip() or None
        flows = self.repo.list_flows(limit=100, host_filter=host_filter)
        stats = self.repo.get_stats()

        self.kpi_var.set(
            f"Total: {stats.total_flows}  ·  Seguras (HTTPS): {stats.https_count}  ·  "
            f"Con avisos: {stats.low_security_count}  ·  Media: {stats.avg_duration_ms} ms"
        )

        for item in self.tree.get_children():
            self.tree.delete(item)
        self.flows_by_id.clear()

        for f in flows:
            self.flows_by_id[f.id] = f
            lock = "🔒" if f.scheme.lower() == "https" else "🔓"
            grade_lbl = f"Nota {f.security_audit.grade} ({f.security_audit.score})"
            self.tree.insert(
                "",
                tk.END,
                iid=str(f.id),
                values=(
                    f.method,
                    f"{lock} {f.host}{f.path}",
                    f"HTTP {f.status_code}",
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
            self._set_text(
                widget,
                "Lista vacía. Pulsa 'Cargar ejemplos' o '＋ Nueva prueba' arriba a la derecha.",
            )

    def on_row_selected(self, _event: object) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        flow = self.flows_by_id.get(int(sel[0]))
        if flow:
            self._render_flow_details(flow)

    def _render_flow_details(self, flow: HttpFlowRecord) -> None:
        audit = flow.security_audit
        sec_lines = [
            f"Nota de Seguridad: {audit.grade} ({audit.score} / 100 puntos)",
            f"Dirección: {flow.method} {flow.url}  (Respuesta {flow.status_code} en {flow.duration_ms:.1f} ms)",
            "─" * 68,
            "",
        ]
        for h_name, explanation in HEADER_EXPLANATIONS.items():
            status_tag = (
                "✖ Falta" if h_name in audit.missing_headers else "✔ Activo"
            )
            sec_lines.append(f"[{status_tag}]  {explanation}")
            sec_lines.append(f"            Cabecera técnica: {h_name}\n")

        self._set_text(self.txt_security, "\n".join(sec_lines))

        hdr_lines = ["Cabeceras enviadas por el navegador:", "─" * 50]
        for k, v in flow.request_headers.items():
            hdr_lines.append(f"{k}: {v}")
        hdr_lines.extend(["", "Cabeceras respondidas por el servidor:", "─" * 50])
        for k, v in flow.response_headers.items():
            hdr_lines.append(f"{k}: {v}")
        self._set_text(self.txt_headers, "\n".join(hdr_lines))

        pay_lines = [
            f"Datos enviados ({flow.request_size} bytes):",
            "─" * 50,
            flow.request_preview or "Sin datos enviados.",
            "",
            f"Respuesta recibida ({flow.response_size} bytes · {flow.content_type}):",
            "─" * 50,
            flow.response_preview or "Sin vista previa de texto.",
        ]
        self._set_text(self.txt_payload, "\n".join(pay_lines))

    def _set_text(self, widget: tk.Text, content: str) -> None:
        bg = "#131B2E" if self.dark_mode else "#FFFFFF"
        fg = "#F8FAFC" if self.dark_mode else "#0F172A"
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

    def action_toggle_theme(self) -> None:
        self.dark_mode = not self.dark_mode
        self._apply_palette()
        self.refresh_data()

    def action_open_simulator(self) -> None:
        win = tk.Toplevel(self.root)
        win.title("＋ Nueva prueba")
        win.geometry("420x290")
        win.transient(self.root)
        win.grab_set()

        frame = ttk.Frame(win, padding=18)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Dirección web (URL):").pack(anchor=tk.W)
        url_var = tk.StringVar(value="https://mi-tienda.ejemplo.es/pagos")
        ttk.Entry(frame, textvariable=url_var, width=45).pack(
            fill=tk.X, pady=(2, 10)
        )

        ttk.Label(frame, text="Tipo de petición:").pack(anchor=tk.W)
        method_var = tk.StringVar(value="POST")
        ttk.Combobox(
            frame,
            textvariable=method_var,
            values=("GET", "POST", "PUT", "DELETE"),
            state="readonly",
        ).pack(fill=tk.X, pady=(2, 10))

        ttk.Label(frame, text="Nivel de seguridad simulado:").pack(anchor=tk.W)
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
                resp_headers = {"Strict-Transport-Security": "max-age=31536000"}
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
                duration_ms=16.0,
                request_size=64,
                response_size=128,
                request_headers=sanitize_headers(
                    {"Host": host, "Authorization": "Bearer secret_token_12345"}
                ),
                response_headers=resp_headers,
                request_preview='{"operacion": "prueba"}',
                response_preview='{"estado": "correcto"}',
                security_audit=audit,
            )
            self.repo.save_flow(dto)
            win.destroy()
            self.refresh_data()

        ttk.Button(frame, text="Analizar petición", command=submit).pack(anchor=tk.E)


def main() -> None:
    root = tk.Tk()
    SitecrackDesktopGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
