from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import init_db
from app.routers import admin, alerts, auth, incidents, telemetry, users
from app.seed import seed


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    seed()
    yield


app = FastAPI(title="AD-Integrated EDR API", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=[o.strip() for o in settings.cors_origins.split(",")],
                   allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
for r in (auth, users, telemetry, alerts, incidents, admin):
    app.include_router(r.router)


@app.get("/api/health")
def health():
    return {"status": "ok", "deployment_mode": settings.deployment_mode, "ad_enabled": settings.ad_enabled}
