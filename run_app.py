"""
Lanzador Unificado de la Aplicación Moderna Sitecrack (run_app.py)

Inicia automáticamente:
1. La base de datos local SQLite WAL con datos de ejemplo iniciales si está vacía.
2. El servidor backend FastAPI (http://127.0.0.1:8000) esperando a que esté 100% listo (/health).
3. Abre la ventana de aplicación moderna (--app) y mantiene el servidor activo.
"""

from __future__ import annotations

import argparse
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path

import uvicorn

from src.api.api_server import app, get_repository, seed_demo_flows
from src.ui.gui_app import main as launch_desktop_gui

# Evitar errores de codificación en consolas Windows (cp1252)
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def _is_port_in_use(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def _wait_until_server_ready(url: str, timeout: float = 8.0) -> bool:
    deadline = time.time() + timeout
    health_url = f"{url}/health"
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(health_url, timeout=1.0) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.15)
    return False


def _start_api_background(host: str, port: int) -> threading.Thread:
    config = uvicorn.Config(app, host=host, port=port, log_level="info")
    server = uvicorn.Server(config)
    thread = threading.Thread(
        target=server.run, name="sitecrack-api-thread", daemon=True
    )
    thread.start()
    return thread


def _find_native_app_browser() -> str | None:
    """Busca Edge o Chrome para abrir una ventana dedicada (--app)."""
    candidates = [
        shutil.which("msedge"),
        shutil.which("chrome"),
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    ]
    for path in candidates:
        if path and Path(path).exists():
            return str(path)
    return None


def _open_ui_window(url: str, force_tab: bool = False) -> None:
    browser_bin = _find_native_app_browser()
    if browser_bin and not force_tab:
        subprocess.Popen(
            [
                browser_bin,
                f"--app={url}",
                "--window-size=1380,860",
            ],
            shell=False,
        )
    else:
        webbrowser.open(url)


def main() -> None:
    parser = argparse.ArgumentParser(description="Lanzador de la App Gráfica Sitecrack")
    parser.add_argument(
        "--tk",
        action="store_true",
        help="Usa la interfaz clásica Tkinter en lugar de la ventana moderna.",
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help="Abre la interfaz moderna en una pestaña normal del navegador.",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Solo levanta el servidor sin abrir ventana nueva.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host del backend FastAPI")
    parser.add_argument(
        "--port", type=int, default=8000, help="Puerto del backend FastAPI"
    )
    args = parser.parse_args()

    repo = get_repository()
    if len(repo.list_flows(limit=1)) == 0:
        seed_demo_flows(repo=repo)

    url = f"http://{args.host}:{args.port}"

    if args.tk:
        if not _is_port_in_use(args.host, args.port):
            _start_api_background(args.host, args.port)
            _wait_until_server_ready(url)
        launch_desktop_gui()
        return

    if _is_port_in_use(args.host, args.port):
        print(f"[OK] El servidor Sitecrack ya esta activo en {url}")
        if not args.no_browser:
            _open_ui_window(url, force_tab=args.web)
        return

    print(f"[+] Iniciando servidor Sitecrack en {url} ...")
    _start_api_background(args.host, args.port)

    if _wait_until_server_ready(url):
        print(f"[OK] Servidor listo en {url}")
        if not args.no_browser:
            print("[+] Abriendo ventana grafica de Sitecrack...")
            _open_ui_window(url, force_tab=args.web)
    else:
        print("[!] El servidor tardo mas de lo esperado, abriendo URL...")
        if not args.no_browser:
            webbrowser.open(url)

    print("==================================================================")
    print(f"  Sitecrack App esta ejecutandose en: {url}")
    print("  No cierres esta consola mientras uses la aplicacion.")
    print("  Presiona Ctrl+C aqui cuando quieras apagar el servidor.")
    print("==================================================================")
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[!] Servidor Sitecrack detenido.")


if __name__ == "__main__":
    main()
