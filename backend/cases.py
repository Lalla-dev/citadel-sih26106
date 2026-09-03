"""
Citadel Security Platform - SOC Case Management & Incident Triage Engine (Phase 7)
Provides operational incident triage, lifecycle management, and analyst collaboration:
  - Lifecycle states: NEW, TRIAGED, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE
  - Analyst assignment and timestamped investigation notes
  - Multi-factor filtering (severity, lifecycle status, full-text search)
  - Seamless re-hydration of complete forensic AnalysisResults
"""
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from backend.schemas import AnalysisResult

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
    In-memory case management repository.
    Tracks all analyzed incidents and provides query, triage, and note-taking interfaces.
    """
    def __init__(self):
        self._cases: Dict[str, CaseTicket] = {}

    def create_or_update_from_analysis(self, result: AnalysisResult) -> CaseTicket:
        """
        Creates a new CaseTicket or updates an existing ticket with fresh analysis data.
        Preserves existing status, analyst assignment, and notes if case_id exists.
        """
        now = datetime.now(timezone.utc).isoformat()
        existing = self._cases.get(result.case_id)

        status = existing.status if existing else "NEW"
        analyst = existing.assigned_analyst if existing else "Unassigned"
        notes = existing.notes if existing else []

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
        return self._cases.get(case_id)

    def update_status(self, case_id: str, status: str, analyst: Optional[str] = None) -> Optional[CaseTicket]:
        """
        Updates the incident lifecycle status and optionally re-assigns an analyst.
        """
        ticket = self._cases.get(case_id)
        if not ticket:
            return None

        status_norm = status.upper().strip()
        if status_norm not in VALID_STATUSES:
            raise ValueError(f"Invalid status '{status}'. Must be one of: {', '.join(VALID_STATUSES)}")

        old_status = ticket.status
        ticket.status = status_norm
        ticket.updated_at = datetime.now(timezone.utc).isoformat()

        if analyst:
            ticket.assigned_analyst = analyst

        # Automatically record a system note for the audit log
        ticket.notes.append(CaseNote(
            author="Citadel SOC Engine",
            timestamp=ticket.updated_at,
            note=f"Status transitioned from {old_status} to {status_norm} (Assigned: {ticket.assigned_analyst})"
        ))

        return ticket

    def add_note(self, case_id: str, note_text: str, author: str = "SOC Analyst") -> Optional[CaseTicket]:
        """Adds an analyst investigation note to the case ticket."""
        ticket = self._cases.get(case_id)
        if not ticket:
            return None

        now = datetime.now(timezone.utc).isoformat()
        ticket.notes.append(CaseNote(
            author=author,
            timestamp=now,
            note=note_text.strip()
        ))
        ticket.updated_at = now
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


# Global singleton repository instance
_case_repository = CaseRepository()

def get_case_repository() -> CaseRepository:
    global _case_repository
    return _case_repository
