"""
Lanzador Unificado de la Aplicación Moderna Sitecrack (run_app.py)

Inicia automáticamente:
1. La base de datos local SQLite WAL con datos de ejemplo iniciales si está vacía.
2. El servidor backend FastAPI en segundo plano (http://127.0.0.1:8000).
3. Una ventana de aplicación moderna nativa (--app) o el modo escritorio clásico (--tk).

Ejecución:
    python run_app.py          # Abre la App Moderna en ventana dedicada de escritorio
    python run_app.py --tk     # Abre la ventana clásica Tkinter
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import threading
import time
import webbrowser
from pathlib import Path

import uvicorn

from src.api.api_server import app, get_repository, seed_demo_flows
from src.ui.gui_app import main as launch_desktop_gui


def _start_api_background(host: str, port: int) -> threading.Thread:
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(
        target=server.run, name="sitecrack-api-thread", daemon=True
    )
    thread.start()
    return thread


def _find_native_app_browser() -> str | None:
    """Busca Edge o Chrome para abrir una ventana nativa sin barra de direcciones (--app)."""
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
        help="Abre la interfaz moderna en una pestaña del navegador.",
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
    _start_api_background(args.host, args.port)
    time.sleep(0.7)

    if args.tk:
        launch_desktop_gui()
        return

    browser_bin = _find_native_app_browser()
    if browser_bin and not args.web:
        print(f"[+] Abriendo ventana de aplicación moderna Sitecrack ({url})...")
        proc = subprocess.Popen(
            [
                browser_bin,
                f"--app={url}",
                "--window-size=1380,860",
            ],
            shell=False,
        )
        try:
            proc.wait()
        except KeyboardInterrupt:
            proc.terminate()
    else:
        print(f"[+] Abriendo Sitecrack en {url} ...")
        webbrowser.open(url)
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
