#!/usr/bin/env bash
set -e; cd "$(dirname "$0")/.."
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements-dev.txt
[ -f .env ] || cp .env.example .env
(cd frontend && npm install && npm run build)
echo "Done. Start with: . .venv/bin/activate && python run_server.py"
