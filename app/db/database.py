"""
app/db/database.py
==================
SQLite database setup using SQLAlchemy ORM.

WHY SQLITE:
    SQLite is sufficient for Phase 1 because:
    (a) The dataset is small (~13K rows).
    (b) It requires zero infrastructure (no separate DB server).
    (c) The file is queryable by the Phase 2 learning component directly.
    (d) It is easy to inspect with any SQLite browser for debugging.

    Switching to PostgreSQL in Phase 3 (if needed for concurrent multi-analyst
    use in a live pilot) requires only changing the DATABASE_URL — the ORM
    models and query logic stay identical.

WHY SQLALCHEMY (not raw sqlite3):
    ORM gives us:
    (a) Type-safe model definitions — schema is documented in code.
    (b) Easy migration path to PostgreSQL in Phase 3.
    (c) Parameterised queries by default (no SQL injection surface).
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from pathlib import Path

# Database file lives in the project root under data/ so the Phase 2
# learning scripts can read it directly alongside the CSV files.
DB_PATH = Path(__file__).parent.parent.parent / "data" / "soc_assistant.db"
DATABASE_URL = f"sqlite:///{DB_PATH}"

# check_same_thread=False is required for FastAPI's async request handling.
# SQLite's threading limitation is acceptable at Phase 1 scale.
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False,  # Set True to log all SQL for debugging
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """
    FastAPI dependency: yields a DB session per request, always closing it.
    Usage: db: Session = Depends(get_db) in endpoint function signatures.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """
    Create all tables defined in models.py.
    Called once at application startup (app/main.py lifespan).
    Safe to call multiple times — create_all is idempotent.
    """
    # Import here to ensure models are registered with Base before create_all
    from app.db import models  # noqa: F401
    Base.metadata.create_all(bind=engine)
