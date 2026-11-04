#!/usr/bin/env bash
# ==============================================================================
# Sitecrack - Inicializador de Estructura y Entorno Virtual (Linux / macOS / WSL)
# Principios SOLID | Bajo Acoplamiento | Alta Cohesión
# ==============================================================================
set -euo pipefail

echo "[+] Creando arquitectura modular de directorios Sitecrack..."
mkdir -p src/{domain,core,api,ui} tests scripts data
touch src/__init__.py src/domain/__init__.py src/core/__init__.py src/api/__init__.py src/ui/__init__.py

echo "[+] Inicializando entorno virtual ligero (venv)..."
python3 -m venv venv
# shellcheck disable=SC1091
source venv/bin/activate

echo "[+] Actualizando pip e instalando dependencias..."
python -m pip install --upgrade pip
pip install -r requirements.txt

echo "[✔] Entorno Sitecrack aprovisionado con éxito."
echo "    1. Iniciar Backend API:   uvicorn src.api.api_server:app --host 127.0.0.1 --port 8000"
echo "    2. Iniciar Proxy Core:    mitmdump -s src/core/proxy_core.py --listen-host 127.0.0.1 -p 8080"
echo "    3. Iniciar Consola TUI:   python -m src.ui.cli_app"
