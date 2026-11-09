"""Database engine/session handling (PostgreSQL in the lab, SQLite for quick local runs)."""
from sqlalchemy import create_engine, inspect, text
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


# Columns added after the first release. create_all() never alters existing tables, so add them in place.
_NEW_COLUMNS = {
    "system_users": {"totp_secret_enc": ("VARCHAR(512)", None), "totp_confirmed": ("BOOLEAN", "bool0"),
                     "totp_last_step": ("INTEGER", "0"), "must_change_password": ("BOOLEAN", "bool0"),
                     "token_version": ("INTEGER", "0")},
    "biometric_verifications": {"attempts": ("INTEGER", "0")},
}


def migrate_columns(engine) -> None:
    insp = inspect(engine)
    false = "FALSE" if engine.dialect.name == "postgresql" else "0"
    with engine.begin() as conn:
        for table, cols in _NEW_COLUMNS.items():
            if table not in insp.get_table_names():
                continue
            have = {c["name"] for c in insp.get_columns(table)}
            for name, (ddl, default) in cols.items():
                if name not in have:
                    d = false if default == "bool0" else default
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}" + (f" DEFAULT {d}" if d is not None else "")))
