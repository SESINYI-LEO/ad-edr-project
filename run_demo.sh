#!/usr/bin/env bash
# Start the server against the evaluation database (used for screenshots)
cd "$(dirname "$0")"
export DATABASE_URL=${DATABASE_URL:-postgresql+psycopg2://postgres@localhost:5433/edr_eval} BACKUP_DIR=$PWD/data/backups BACKUP_KEY=eval-backup-key-0123456789 SECRET_KEY=eval-secret-key-eval-secret-key-1234 FRONTEND_DIR=$PWD/frontend/dist
exec python run_server.py
