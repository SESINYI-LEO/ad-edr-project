import logging

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import settings

_kwargs = {"connect_args": {"check_same_thread": False}} if settings.database_url.startswith("sqlite") else {"pool_pre_ping": True}
engine = create_engine(settings.database_url, **_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


log = logging.getLogger("edr.database")


def add_missing_columns(eng=None) -> list[str]:
    """create_all() never alters existing tables, so a database created before a column was added would break.
    Add any missing *nullable* column in place (works on SQLite and PostgreSQL). Returns what was added."""
    eng = eng or engine
    insp = inspect(eng)
    added = []
    with eng.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if not insp.has_table(table.name):
                continue
            have = {c["name"] for c in insp.get_columns(table.name)}
            for col in table.columns:
                if col.name in have:
                    continue
                if not col.nullable:
                    log.warning("Column %s.%s is missing and NOT NULL; add it by hand", table.name, col.name)
                    continue
                conn.execute(text(f'ALTER TABLE {table.name} ADD COLUMN {col.name} {col.type.compile(dialect=eng.dialect)}'))
                added.append(f"{table.name}.{col.name}")
    return added


def init_db():
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    added = add_missing_columns()
    if added:
        log.warning("Upgraded database, added columns: %s", ", ".join(added))
