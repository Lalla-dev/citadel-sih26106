"""
Citadel Security Platform - Relational Persistence Layer (Phase 6)
Provides relational database storage for SOC cases, lifecycle state,
analyst notes, audit events, and cryptographic evidence ledger blocks.

Supported backends:
  1. PostgreSQL (production / enterprise demo): Activated via DATABASE_URL environment variable.
     If PostgreSQL is specified but cannot be reached, Citadel fails clearly with an explicit error.
  2. SQLite (local SIH evaluation fallback): Used when DATABASE_URL is omitted.
     Persists to ./citadel_persistence.db so cases, notes, and evidence survive process restarts.
"""
import os
import json
import logging
from typing import Optional, Generator
from datetime import datetime, timezone
from contextlib import contextmanager

from sqlalchemy import (
    create_engine,
    Column,
    String,
    Integer,
    Float,
    Text,
    Boolean,
    LargeBinary,
    ForeignKey,
    Index,
    select
)
from sqlalchemy.orm import (
    declarative_base,
    sessionmaker,
    relationship,
    Session
)

logger = logging.getLogger("citadel.persistence")

Base = declarative_base()


# --------------------------------------------------------------------------
# Database Models
# --------------------------------------------------------------------------

class CaseModel(Base):
    """Stores SOC case ticket records and complete forensic AnalysisResult data."""
    __tablename__ = "cases"

    case_id = Column(String(64), primary_key=True, index=True)
    created_at = Column(String(64), nullable=False, index=True)
    updated_at = Column(String(64), nullable=False)
    filename = Column(String(255), nullable=False)
    subject = Column(Text, nullable=False)
    sender = Column(Text, nullable=False)
    recipient = Column(Text, nullable=False)
    threat_score = Column(Integer, nullable=False, index=True)
    risk_level = Column(String(32), nullable=False, index=True)
    threat_archetype = Column(String(128), nullable=False)
    confidence = Column(Float, nullable=False)
    status = Column(String(32), nullable=False, default="NEW", index=True)
    assigned_analyst = Column(String(128), nullable=False, default="Unassigned")
    analysis_result_json = Column(Text, nullable=True)

    notes = relationship("CaseNoteModel", back_populates="case", cascade="all, delete-orphan", order_by="CaseNoteModel.id")


class CaseNoteModel(Base):
    """Stores analyst investigation notes and automated lifecycle audit transitions."""
    __tablename__ = "case_notes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False, index=True)
    author = Column(String(128), nullable=False)
    timestamp = Column(String(64), nullable=False)
    note = Column(Text, nullable=False)
    is_audit = Column(Boolean, default=False, nullable=False)

    case = relationship("CaseModel", back_populates="notes")


class EvidenceLedgerBlockModel(Base):
    """Stores append-only cryptographic evidence ledger blocks and raw RFC 5322 bytes."""
    __tablename__ = "evidence_ledger_blocks"

    block_index = Column(Integer, primary_key=True)
    timestamp = Column(String(64), nullable=False)
    case_id = Column(String(64), nullable=False, index=True)
    evidence_sha256 = Column(String(64), nullable=False)
    verdict_sha256 = Column(String(64), nullable=False)
    previous_block_hash = Column(String(64), nullable=False)
    merkle_root = Column(String(64), nullable=False)
    block_hash = Column(String(64), nullable=False)
    raw_eml_bytes = Column(LargeBinary, nullable=False)
    headers_json = Column(Text, nullable=False)
    verdict_json = Column(Text, nullable=False)


class AuditLogModel(Base):
    """Stores immutable audit log records for SOC compliance and security monitoring."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(String(64), nullable=False, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    case_id = Column(String(64), nullable=True, index=True)
    actor = Column(String(128), nullable=False)
    details = Column(Text, nullable=True)


# --------------------------------------------------------------------------
# Engine & Session Management
# --------------------------------------------------------------------------

_engine = None
_SessionFactory = None
_active_backend = None
DEFAULT_SQLITE_URL = "sqlite:///./citadel_persistence.db"


def resolve_database_url() -> tuple[str, str]:
    """
    Resolves the active database URL according to strict rules:
      - If DATABASE_URL is set and starts with postgresql:// or postgresql+psycopg2://: use PostgreSQL.
      - If DATABASE_URL is omitted or empty: use local persistent SQLite.
    Returns (url, backend_type).
    """
    raw_url = os.environ.get("DATABASE_URL", "").strip()
    if raw_url:
        if raw_url.startswith(("postgresql://", "postgresql+psycopg2://")):
            return raw_url, "PostgreSQL"
        else:
            return raw_url, "Custom SQL"
    return DEFAULT_SQLITE_URL, "SQLite (Local Persistent)"


def get_active_backend() -> str:
    """Returns the name of the currently active database backend."""
    global _active_backend
    if not _active_backend:
        _, backend = resolve_database_url()
        _active_backend = backend
    return _active_backend


def create_citadel_engine(database_url: Optional[str] = None):
    """
    Creates and validates an SQLAlchemy engine.
    Fails explicitly if PostgreSQL was requested but cannot connect.
    """
    if database_url:
        target_url = database_url
        target_backend = "PostgreSQL" if "postgres" in target_url.lower() else "Custom/SQLite"
    else:
        target_url, target_backend = resolve_database_url()

    connect_args = {}
    if target_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False

    engine = create_engine(target_url, connect_args=connect_args, echo=False)

    # Validate connection immediately
    try:
        with engine.connect() as conn:
            pass
    except Exception as exc:
        if "postgres" in target_url.lower():
            err_msg = (
                f"[Citadel Persistence Error] Failed to connect to PostgreSQL at '{target_url}'. "
                f"DATABASE_URL was explicitly provided, so Citadel will NOT silently fall back to SQLite. "
                f"Root cause: {str(exc)}"
            )
            logger.error(err_msg)
            raise ConnectionError(err_msg) from exc
        else:
            raise

    return engine, target_backend


def init_db(database_url: Optional[str] = None):
    """
    Initializes the database connection and creates all required tables.
    Logs startup status to stdout so the active backend is immediately clear.
    """
    global _engine, _SessionFactory, _active_backend
    engine, backend = create_citadel_engine(database_url)
    _engine = engine
    _active_backend = backend
    _SessionFactory = sessionmaker(bind=_engine, expire_on_commit=False)

    # Create tables if not already existing
    Base.metadata.create_all(bind=_engine)

    print(f"[Citadel Persistence] Active Database Backend: {_active_backend}")
    logger.info(f"Citadel persistence initialized. Backend: {_active_backend}")


def get_engine():
    """Returns the active SQLAlchemy engine, initializing if necessary."""
    global _engine
    if _engine is None:
        init_db()
    return _engine


def get_session_factory():
    """Returns the active sessionmaker."""
    global _SessionFactory
    if _SessionFactory is None:
        init_db()
    return _SessionFactory


@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """Context manager providing a transactional database session."""
    factory = get_session_factory()
    session: Session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def record_audit_log(
    event_type: str,
    actor: str,
    case_id: Optional[str] = None,
    details: Optional[str] = None
) -> None:
    """Convenience helper to record an immutable audit log entry."""
    try:
        with get_db_session() as session:
            log_entry = AuditLogModel(
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type=event_type,
                case_id=case_id,
                actor=actor,
                details=details
            )
            session.add(log_entry)
    except Exception as e:
        logger.warning(f"Failed to record audit log: {str(e)}")
