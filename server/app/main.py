"""Application factory for the AD-integrated EDR server."""
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from . import db as dbm
from .ad import Directory
from .config import get_settings
from .detection import Detector, load_rules
from .models import Base, DetectionRule, SystemUser
from .routes import admin, agent, auth, incidents, ops
from .security import hash_password


def seed(session, s, rules):
    """Sync rules from YAML (preserving the enabled flag) and create the default accounts."""
    existing = {r.rule_id: r for r in session.query(DetectionRule)}
    for r in rules:
        row = existing.get(r.id) or DetectionRule(rule_id=r.id, enabled=True)
        row.name, row.description, row.severity = r.name, r.description, r.severity
        row.attack_technique_id, row.attack_tactic, row.confidence = r.technique, r.tactic, r.confidence
        session.add(row)
        r.enabled = row.enabled
    if session.query(SystemUser).count() == 0:
        admin_pw = os.environ.get("ADMIN_PASSWORD", "Admin@EDR-2026!")
        analyst_pw = os.environ.get("ANALYST_PASSWORD", "Analyst@EDR-2026!")
        session.add_all([
            SystemUser(username="admin", full_name="Local Administrator", role="admin", auth_source="local",
                       password_hash=hash_password(admin_pw)),
            SystemUser(username="analyst", full_name="Local Analyst", role="analyst", auth_source="local",
                       password_hash=hash_password(analyst_pw)),
            SystemUser(username="admin01", full_name="Sam Administrator (AD)", role="admin", auth_source="ad"),
            SystemUser(username="analyst01", full_name="Neo Analyst (AD)", role="analyst", auth_source="ad"),
        ])
    session.commit()


def create_app(database_url: str | None = None) -> FastAPI:
    s = get_settings()
    engine = dbm.init_engine(database_url or s.database_url)
    Base.metadata.create_all(engine)
    rules = load_rules(s.rules_file)
    with dbm.SessionLocal() as session:
        seed(session, s, rules)

    @asynccontextmanager
    async def lifespan(app):
        yield
        engine.dispose()

    app = FastAPI(title="AD-Integrated EDR", version="1.0.0", lifespan=lifespan)
    app.state.directory = Directory(s)
    app.state.detector = Detector(rules)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Content-Security-Policy",
                                "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'")
        return resp

    @app.get("/api/v1/health")
    def health():
        with dbm.SessionLocal() as session:
            session.execute(text("SELECT 1"))
        return {"status": "ok", "ad_mode": s.ad_mode}

    for r in (auth.router, agent.router, ops.router, incidents.router, admin.router):
        app.include_router(r)

    dist = Path(s.frontend_dir)
    if dist.is_dir():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets") if (dist / "assets").is_dir() else None

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str):
            if path.startswith("api/"):
                return JSONResponse({"detail": "Not found"}, status_code=404)
            f = (dist / path).resolve()
            if path and f.is_file() and dist.resolve() in f.parents:
                return FileResponse(f)
            return FileResponse(dist / "index.html")

    return app
