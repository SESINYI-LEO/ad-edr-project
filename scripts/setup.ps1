# Windows one-shot setup:  powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot)
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements-dev.txt
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
Push-Location frontend; npm install; npm run build; Pop-Location
Write-Host "Done. Start with: .\.venv\Scripts\python run_server.py"
