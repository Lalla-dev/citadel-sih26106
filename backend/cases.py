"""
Citadel Security Platform - SOC Case Management & Incident Triage Engine (Phase 6 & 7)
Provides operational incident triage, lifecycle management, and analyst collaboration
backed by relational persistence (PostgreSQL / SQLite):
  - Lifecycle states: NEW, TRIAGED, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE
  - Analyst assignment and timestamped investigation notes
  - Multi-factor filtering (severity, lifecycle status, full-text search)
  - Seamless re-hydration of complete forensic AnalysisResults across restarts
"""
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from backend.schemas import AnalysisResult
from backend.database import (
    get_db_session,
    CaseModel,
    CaseNoteModel,
    AuditLogModel,
    record_audit_log,
    init_db
)

logger = logging.getLogger("citadel.cases")

VALID_STATUSES = ["NEW", "TRIAGED", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"]


class CaseNote(BaseModel):
    author: str = "SOC Analyst"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    note: str


class CaseStatusUpdate(BaseModel):
    status: str
    analyst: Optional[str] = None


class CaseNoteCreate(BaseModel):
    note: str
    author: str = "SOC Analyst"


class CaseTicket(BaseModel):
    case_id: str
    created_at: str
    updated_at: str
    filename: str
    subject: str
    sender: str
    recipient: str
    threat_score: int
    risk_level: str
    threat_archetype: str
    confidence: float
    status: str = "NEW"
    assigned_analyst: str = "Unassigned"
    notes: List[CaseNote] = Field(default_factory=list)
    analysis_result: Optional[AnalysisResult] = None


class CaseRepository:
    """
    Relational case management repository backed by PostgreSQL/SQLite.
    Tracks all analyzed incidents and provides query, triage, and note-taking interfaces.
    All data is persisted to disk/database and survives process restarts.
    """
    def __init__(self, load_from_db: bool = False, persist_to_db: Optional[bool] = None):
        self._cases: Dict[str, CaseTicket] = {}
        should_load = load_from_db or (persist_to_db is True)
        if should_load:
            self.load_from_db()

    def load_from_db(self) -> None:
        """Loads all persisted cases and notes from the database into memory."""
        try:
            with get_db_session() as session:
                models = session.execute(
                    select(CaseModel).options(selectinload(CaseModel.notes)).order_by(CaseModel.created_at.desc())
                ).scalars().all()
                for m in models:
                    self._cases[m.case_id] = self._model_to_ticket(m)
        except Exception as e:
            logger.warning(f"Could not load cases from database: {e}")

    def _model_to_ticket(self, model: CaseModel) -> CaseTicket:
        """Converts an SQLAlchemy CaseModel into a Pydantic CaseTicket."""
        notes = [
            CaseNote(
                author=n.author,
                timestamp=n.timestamp,
                note=n.note
            )
            for n in model.notes
        ]

        analysis_res = None
        if model.analysis_result_json:
            try:
                analysis_res = AnalysisResult.model_validate_json(model.analysis_result_json)
            except Exception:
                try:
                    analysis_res = AnalysisResult(**json.loads(model.analysis_result_json))
                except Exception:
                    pass

        return CaseTicket(
            case_id=model.case_id,
            created_at=model.created_at,
            updated_at=model.updated_at,
            filename=model.filename,
            subject=model.subject,
            sender=model.sender,
            recipient=model.recipient,
            threat_score=model.threat_score,
            risk_level=model.risk_level,
            threat_archetype=model.threat_archetype,
            confidence=model.confidence,
            status=model.status,
            assigned_analyst=model.assigned_analyst,
            notes=notes,
            analysis_result=analysis_res
        )

    def create_or_update_from_analysis(self, result: AnalysisResult) -> CaseTicket:
        """
        Creates a new CaseTicket or updates an existing ticket with fresh analysis data.
        Preserves existing status, analyst assignment, and notes if case_id exists.
        Persists changes directly to the database.
        """
        now = datetime.now(timezone.utc).isoformat()
        res_json = result.model_dump_json()

        existing = self._cases.get(result.case_id)
        status = existing.status if existing else "NEW"
        analyst = existing.assigned_analyst if existing else "Unassigned"
        notes = list(existing.notes) if existing else []

        sender_str = result.metadata.sender_display_name or result.metadata.sender_email or "Unknown Sender"
        if result.metadata.sender_display_name and result.metadata.sender_email:
            sender_str = f"{result.metadata.sender_display_name} <{result.metadata.sender_email}>"

        ticket = CaseTicket(
            case_id=result.case_id,
            created_at=existing.created_at if existing else result.timestamp or now,
            updated_at=now,
            filename=result.filename,
            subject=result.metadata.subject or "(No Subject)",
            sender=sender_str,
            recipient=result.metadata.recipient or "(No Recipient)",
            threat_score=result.threat_score,
            risk_level=result.risk_level,
            threat_archetype=result.threat_archetype,
            confidence=result.confidence,
            status=status,
            assigned_analyst=analyst,
            notes=notes,
            analysis_result=result
        )
        self._cases[result.case_id] = ticket

        # Persist to database
        try:
            with get_db_session() as session:
                db_model = session.execute(
                    select(CaseModel).where(CaseModel.case_id == result.case_id).options(selectinload(CaseModel.notes))
                ).scalar_one_or_none()

                if db_model:
                    db_model.updated_at = now
                    db_model.filename = result.filename
                    db_model.subject = ticket.subject
                    db_model.sender = ticket.sender
                    db_model.recipient = ticket.recipient
                    db_model.threat_score = result.threat_score
                    db_model.risk_level = result.risk_level
                    db_model.threat_archetype = result.threat_archetype
                    db_model.confidence = result.confidence
                    db_model.analysis_result_json = res_json
                else:
                    new_case = CaseModel(
                        case_id=result.case_id,
                        created_at=ticket.created_at,
                        updated_at=now,
                        filename=result.filename,
                        subject=ticket.subject,
                        sender=ticket.sender,
                        recipient=ticket.recipient,
                        threat_score=result.threat_score,
                        risk_level=result.risk_level,
                        threat_archetype=result.threat_archetype,
                        confidence=result.confidence,
                        status=status,
                        assigned_analyst=analyst,
                        analysis_result_json=res_json
                    )
                    session.add(new_case)
        except Exception as e:
            logger.warning(f"Could not persist case {result.case_id}: {e}")

        record_audit_log(
            event_type="CASE_CREATED",
            actor="Citadel Ingestion Engine",
            case_id=result.case_id,
            details=f"Threat Score: {result.threat_score}, Archetype: {result.threat_archetype}"
        )

        return ticket

    def list_cases(
        self,
        status: Optional[str] = None,
        risk_level: Optional[str] = None,
        search: Optional[str] = None
    ) -> List[CaseTicket]:
        """
        Retrieves all cases filtered by status, risk_level, or search query.
        Returns list sorted by created_at descending (newest first).
        """
        cases = list(self._cases.values())

        # Filter by status
        if status and status.upper() != "ALL":
            st_upper = status.upper()
            cases = [c for c in cases if c.status.upper() == st_upper]

        # Filter by risk level
        if risk_level and risk_level.upper() != "ALL":
            rl_upper = risk_level.upper()
            cases = [c for c in cases if c.risk_level.upper() == rl_upper]

        # Search across case_id, subject, sender, recipient, archetype
        if search:
            q = search.lower().strip()
            cases = [
                c for c in cases
                if q in c.case_id.lower()
                or q in c.subject.lower()
                or q in c.sender.lower()
                or q in c.recipient.lower()
                or q in c.threat_archetype.lower()
            ]

        # Sort newest first
        cases.sort(key=lambda c: c.created_at, reverse=True)
        return cases

    def get_case(self, case_id: str) -> Optional[CaseTicket]:
        """Retrieves a single case ticket by case_id."""
        if case_id in self._cases:
            return self._cases[case_id]

        # Check database fallback
        try:
            with get_db_session() as session:
                model = session.execute(
                    select(CaseModel).where(CaseModel.case_id == case_id).options(selectinload(CaseModel.notes))
                ).scalar_one_or_none()
                if model:
                    ticket = self._model_to_ticket(model)
                    self._cases[case_id] = ticket
                    return ticket
        except Exception as e:
            logger.warning(f"Could not fetch case {case_id} from database: {e}")

        return None

    def update_status(self, case_id: str, status: str, analyst: Optional[str] = None) -> Optional[CaseTicket]:
        """
        Updates the incident lifecycle status and optionally re-assigns an analyst.
        Persists transition to database and records an automated audit note.
        """
        ticket = self.get_case(case_id)
        if not ticket:
            return None

        status_norm = status.upper().strip()
        if status_norm not in VALID_STATUSES:
            raise ValueError(f"Invalid status '{status}'. Must be one of: {', '.join(VALID_STATUSES)}")

        now = datetime.now(timezone.utc).isoformat()
        old_status = ticket.status
        ticket.status = status_norm
        ticket.updated_at = now

        if analyst:
            ticket.assigned_analyst = analyst

        audit_note_text = f"Status transitioned from {old_status} to {status_norm} (Assigned: {ticket.assigned_analyst})"
        audit_note = CaseNote(
            author="Citadel SOC Engine",
            timestamp=now,
            note=audit_note_text
        )
        ticket.notes.append(audit_note)

        # Persist to database
        try:
            with get_db_session() as session:
                model = session.execute(
                    select(CaseModel).where(CaseModel.case_id == case_id).options(selectinload(CaseModel.notes))
                ).scalar_one_or_none()

                if model:
                    model.status = status_norm
                    model.updated_at = now
                    if analyst:
                        model.assigned_analyst = analyst

                    db_note = CaseNoteModel(
                        case_id=case_id,
                        author="Citadel SOC Engine",
                        timestamp=now,
                        note=audit_note_text,
                        is_audit=True
                    )
                    model.notes.append(db_note)
        except Exception as e:
            logger.warning(f"Could not persist status update for {case_id}: {e}")

        record_audit_log(
            event_type="STATUS_CHANGED",
            actor=analyst or "Citadel SOC Engine",
            case_id=case_id,
            details=f"Transition: {old_status} -> {status_norm}"
        )

        return ticket

    def add_note(self, case_id: str, note_text: str, author: str = "SOC Analyst") -> Optional[CaseTicket]:
        """Adds an analyst investigation note to the case ticket and persists to database."""
        ticket = self.get_case(case_id)
        if not ticket:
            return None

        now = datetime.now(timezone.utc).isoformat()
        clean_text = note_text.strip()
        new_note = CaseNote(
            author=author,
            timestamp=now,
            note=clean_text
        )
        ticket.notes.append(new_note)
        ticket.updated_at = now

        # Persist to database
        try:
            with get_db_session() as session:
                model = session.execute(
                    select(CaseModel).where(CaseModel.case_id == case_id).options(selectinload(CaseModel.notes))
                ).scalar_one_or_none()

                if model:
                    model.updated_at = now
                    db_note = CaseNoteModel(
                        case_id=case_id,
                        author=author,
                        timestamp=now,
                        note=clean_text,
                        is_audit=False
                    )
                    model.notes.append(db_note)
        except Exception as e:
            logger.warning(f"Could not persist note for {case_id}: {e}")

        record_audit_log(
            event_type="NOTE_ADDED",
            actor=author,
            case_id=case_id,
            details=clean_text[:120]
        )

        return ticket

    def get_queue_statistics(self) -> Dict[str, Any]:
        """Returns aggregate queue statistics for the SOC dashboard."""
        all_cases = list(self._cases.values())
        return {
            "total_cases": len(all_cases),
            "critical_high": len([c for c in all_cases if c.risk_level in ["CRITICAL", "HIGH"]]),
            "investigating": len([c for c in all_cases if c.status in ["INVESTIGATING", "TRIAGED"]]),
            "contained_resolved": len([c for c in all_cases if c.status in ["CONTAINED", "RESOLVED"]]),
            "by_status": {
                s: len([c for c in all_cases if c.status == s]) for s in VALID_STATUSES
            }
        }


# Global singleton repository instance, loads existing cases on process start
_case_repository = None

def get_case_repository() -> CaseRepository:
    global _case_repository
    if _case_repository is None:
        _case_repository = CaseRepository(load_from_db=True)
    return _case_repository
