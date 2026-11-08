"""Database engine/session handling (PostgreSQL in the lab, SQLite for quick local runs)."""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from .config import get_settings

_engine = None
_Session = None


def init_engine(url: str | None = None):
    global _engine, _Session
    url = url or get_settings().database_url
    kw = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        kw["connect_args"] = {"check_same_thread": False}
        if ":memory:" in url:
            kw["poolclass"] = StaticPool
    else:
        kw.update(pool_size=10, max_overflow=20)
    _engine = create_engine(url, **kw)
    _Session = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)
    return _engine


def get_engine():
    if _engine is None:
        init_engine()
    return _engine


def SessionLocal():
    if _Session is None:
        init_engine()
    return _Session()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
