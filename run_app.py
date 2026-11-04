"""
Lanzador Unificado de la Aplicación Gráfica Sitecrack (run_app.py)

Inicia automáticamente:
1. La base de datos local SQLite WAL con datos de ejemplo iniciales si está vacía.
2. El servidor backend FastAPI en segundo plano (http://127.0.0.1:8000).
3. La aplicación gráfica de escritorio nativa (Tkinter GUI) o la Web App interactiva.

Ejecución:
    python run_app.py          # Abre la App Gráfica de Escritorio + Backend API
    python run_app.py --web    # Abre la App Gráfica Web en navegador (http://127.0.0.1:8000)
"""

from __future__ import annotations

import argparse
import threading
import time
import webbrowser
from typing import Optional

import uvicorn

from src.api.api_server import app, get_repository, seed_demo_flows
from src.ui.gui_app import main as launch_desktop_gui


def _start_api_background(host: str, port: int) -> threading.Thread:
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, name="sitecrack-api-thread", daemon=True)
    thread.start()
    return thread


def main() -> None:
    parser = argparse.ArgumentParser(description="Lanzador de la App Gráfica Sitecrack")
    parser.add_argument(
        "--web",
        action="store_true",
        help="Abre la interfaz gráfica en el navegador web en lugar de la ventana nativa.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host del backend FastAPI")
    parser.add_argument("--port", type=int, default=8000, help="Puerto del backend FastAPI")
    args = parser.parse_args()

    # Asegurar datos de muestra iniciales para que la interfaz nunca aparezca vacía al arrancar
    repo = get_repository()
    if len(repo.list_flows(limit=1)) == 0:
        seed_demo_flows(repo=repo)

    url = f"http://{args.host}:{args.port}"

    if args.web:
        print(f"[+] Iniciando Sitecrack Web App en {url} ...")
        _start_api_background(args.host, args.port)
        time.sleep(0.8)
        webbrowser.open(url)
        print("[✔] Aplicación abierta en el navegador. Presiona Ctrl+C para cerrar.")
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            print("\n[!] Cerrando Sitecrack App.")
    else:
        print(f"[+] Iniciando Backend API en segundo plano ({url}) y abriendo App de Escritorio...")
        _start_api_background(args.host, args.port)
        launch_desktop_gui()


if __name__ == "__main__":
    main()
