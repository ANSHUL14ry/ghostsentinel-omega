"""
GHOSTSENTINEL Ω — Database Initialisation
SQLite + SQLAlchemy 2.x async-compatible setup.
"""
from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from app.core.config import settings
from app.core.logging_config import get_logger

logger = get_logger(__name__)

from sqlalchemy.pool import StaticPool

engine_kwargs = {
    "connect_args": {"check_same_thread": False},
    "echo": False,
}
if ":memory:" in settings.database_url:
    engine_kwargs["poolclass"] = StaticPool

engine = create_engine(settings.database_url, **engine_kwargs)


# Enable WAL mode for better concurrency on file databases
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_conn, connection_record):
    cursor = dbapi_conn.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
    except Exception:
        pass
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
    except Exception:
        pass
    cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    """FastAPI dependency: yields a DB session and ensures cleanup."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables if they do not exist."""
    from app.models import scan, finding, device, network, report, baseline  # noqa: F401
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables initialised at %s", settings.database_url)
