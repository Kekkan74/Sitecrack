<#
.SYNOPSIS
    setup_env.ps1 - Inicializador de Estructura y Entorno Virtual en Windows (PowerShell)
#>
$ErrorActionPreference = "Stop"

Write-Host "[+] Creando arquitectura modular de directorios Sitecrack..." -ForegroundColor Cyan
$dirs = @("src\domain", "src\core", "src\api", "src\ui", "tests", "scripts", "data")
foreach ($d in $dirs) {
    New-Item -ItemType Directory -Path $d -Force | Out-Null
}

Write-Host "[+] Inicializando entorno virtual ligero (venv)..." -ForegroundColor Cyan
python -m venv venv

Write-Host "[+] Instalando dependencias desde requirements.txt..." -ForegroundColor Cyan
.\venv\Scripts\python.exe -m pip install --upgrade pip
.\venv\Scripts\pip.exe install -r requirements.txt

Write-Host "[✔] Entorno Sitecrack aprovisionado con éxito." -ForegroundColor Green
Write-Host "    1. Iniciar Backend API:   .\venv\Scripts\uvicorn.exe src.api.api_server:app --host 127.0.0.1 --port 8000"
Write-Host "    2. Iniciar Proxy Core:    .\venv\Scripts\mitmdump.exe -s src/core/proxy_core.py --listen-host 127.0.0.1 -p 8080"
Write-Host "    3. Iniciar Consola TUI:   .\venv\Scripts\python.exe -m src.ui.cli_app"
