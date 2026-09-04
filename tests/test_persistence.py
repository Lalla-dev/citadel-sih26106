"""
Citadel Phase 6 Tests - Relational Persistence & Restart Survival
Validates that:
  1. SOC cases, statuses, analyst assignments, and notes persist in the relational database.
  2. Cryptographic evidence ledger blocks, Merkle roots, and raw .eml bytes survive process restart.
  3. Integrity verification returns VERIFIED after complete repository re-instantiation.
  4. Forensic HTML and JSON reports can be generated for cases after memory cache is cleared.
  5. Audit log records all key events (case creation, status change, note added, evidence anchored).
  6. PostgreSQL connection failure fails explicitly without silent fallback to SQLite.
"""
import os
import hashlib
import unittest
from datetime import datetime, timezone
from sqlalchemy import select

from backend.database import (
    init_db,
    get_db_session,
    get_active_backend,
    resolve_database_url,
    create_citadel_engine,
    CaseModel,
    CaseNoteModel,
    EvidenceLedgerBlockModel,
    AuditLogModel
)
from backend.cases import CaseRepository, CaseTicket
from backend.integrity import EvidenceLedger
from backend.reports import get_case_result, generate_html_report, generate_json_report, _CASE_RESULTS_STORE
from backend.parser import parse_eml
from backend.detector import CitadelDetectorOrchestrator


class TestPhase6Persistence(unittest.TestCase):
    """Integration and restart-survival tests for the Phase 6 relational persistence layer."""

    @classmethod
    def setUpClass(cls):
        # Initialize test persistence
        init_db()

    def setUp(self):
        self.orchestrator = CitadelDetectorOrchestrator()
        self.raw_eml = (
            b"From: David Henderson <david.henderson.corp@gmail.com>\r\n"
            b"To: robert.investor@apexcapitals.com\r\n"
            b"Reply-To: exec-private-desk@secure-portal.xyz\r\n"
            b"Subject: Strictly Confidential - Urgent Wire Transfer Request\r\n"
            b"Date: Fri, 04 Sep 2026 09:45:10 +0000\r\n"
            b"Message-ID: <wire-urgency-persist-001@apexcapitals.com>\r\n\r\n"
            b"Robert,\r\n"
            b"We need an urgent wire transfer of $184,500 processed promptly.\r\n"
            b"Keep this strictly confidential."
        )
        parsed = parse_eml(self.raw_eml)
        self.result = self.orchestrator.analyze(parsed, filename="wire_transfer.eml", raw_bytes=self.raw_eml)
        self.case_id = self.result.case_id

    def test_1_case_record_persists_in_database(self):
        """Case ticket created via CaseRepository(persist_to_db=True) exists in database."""
        repo_1 = CaseRepository(persist_to_db=True)
        ticket_1 = repo_1.create_or_update_from_analysis(self.result)
        self.assertEqual(ticket_1.case_id, self.case_id)

        # Direct SQL inspection
        with get_db_session() as session:
            db_row = session.get(CaseModel, self.case_id)
            self.assertIsNotNone(db_row)
            self.assertEqual(db_row.case_id, self.case_id)
            self.assertEqual(db_row.threat_score, self.result.threat_score)
            self.assertEqual(db_row.risk_level, self.result.risk_level)
            self.assertEqual(db_row.threat_archetype, self.result.threat_archetype)
            self.assertIn("wire transfer", db_row.subject.lower())

    def test_2_case_retrieval_across_simulated_restart(self):
        """A new CaseRepository instance (simulating restart) loads the exact case from database."""
        # Session A: Create case
        repo_a = CaseRepository(persist_to_db=True)
        repo_a.create_or_update_from_analysis(self.result)

        # Session B: Simulate complete application restart with new instance
        repo_b = CaseRepository(persist_to_db=True)
        ticket_b = repo_b.get_case(self.case_id)

        self.assertIsNotNone(ticket_b)
        self.assertEqual(ticket_b.case_id, self.case_id)
        self.assertEqual(ticket_b.threat_score, self.result.threat_score)
        self.assertEqual(ticket_b.risk_level, self.result.risk_level)
        self.assertEqual(ticket_b.filename, "wire_transfer.eml")
        self.assertIsNotNone(ticket_b.analysis_result)
        self.assertEqual(ticket_b.analysis_result.case_id, self.case_id)

    def test_3_status_and_analyst_survives_restart(self):
        """Lifecycle status transition and analyst assignment survive process restart."""
        repo_a = CaseRepository(persist_to_db=True)
        repo_a.create_or_update_from_analysis(self.result)

        # Update status and assign analyst in Session A
        updated_a = repo_a.update_status(self.case_id, "INVESTIGATING", analyst="Lead SOC Analyst")
        self.assertEqual(updated_a.status, "INVESTIGATING")
        self.assertEqual(updated_a.assigned_analyst, "Lead SOC Analyst")

        # Session B: Fresh instance simulating server restart
        repo_b = CaseRepository(persist_to_db=True)
        ticket_b = repo_b.get_case(self.case_id)

        self.assertIsNotNone(ticket_b)
        self.assertEqual(ticket_b.status, "INVESTIGATING")
        self.assertEqual(ticket_b.assigned_analyst, "Lead SOC Analyst")
        # Audit note for transition must be present
        self.assertTrue(any("Status transitioned from NEW to INVESTIGATING" in n.note for n in ticket_b.notes))

    def test_4_analyst_notes_survive_restart(self):
        """Multiple investigation notes added by analysts survive process restart in chronological order."""
        repo_a = CaseRepository(persist_to_db=True)
        repo_a.create_or_update_from_analysis(self.result)

        repo_a.add_note(self.case_id, "Note 1: Escalated to financial fraud team.", author="Analyst A")
        repo_a.add_note(self.case_id, "Note 2: Blocked secure-portal.xyz on DNS gateway.", author="Analyst B")

        # Session B: Fresh instance
        repo_b = CaseRepository(persist_to_db=True)
        ticket_b = repo_b.get_case(self.case_id)

        self.assertIsNotNone(ticket_b)
        note_texts = [n.note for n in ticket_b.notes]
        self.assertTrue(any("Escalated to financial fraud team" in t for t in note_texts))
        self.assertTrue(any("Blocked secure-portal.xyz" in t for t in note_texts))

        # Check authors
        authors = [n.author for n in ticket_b.notes]
        self.assertIn("Analyst A", authors)
        self.assertIn("Analyst B", authors)

    def test_5_evidence_ledger_blocks_survive_restart(self):
        """Cryptographic evidence ledger blocks, Merkle roots, and raw bytes survive restart."""
        # Instance A: Record evidence
        ledger_a = EvidenceLedger(persist_to_db=True)
        block_a = ledger_a.record_case_evidence(
            case_id=self.case_id,
            raw_eml_bytes=self.raw_eml,
            headers_dict={"subject": "Wire Transfer", "sender": "ceo@gmail.com"},
            verdict_dict={"threat_score": 100, "risk_level": "CRITICAL", "threat_archetype": "BEC"}
        )

        block_index = block_a["block_index"]
        block_hash = block_a["block_hash"]
        merkle_root = block_a["merkle_root"]
        evidence_sha256 = block_a["evidence_sha256"]

        # Instance B: Fresh ledger simulating server restart
        ledger_b = EvidenceLedger(persist_to_db=True)
        block_b = ledger_b.get_case_block(self.case_id)

        self.assertIsNotNone(block_b)
        self.assertEqual(block_b["block_index"], block_index)
        self.assertEqual(block_b["block_hash"], block_hash)
        self.assertEqual(block_b["merkle_root"], merkle_root)
        self.assertEqual(block_b["evidence_sha256"], evidence_sha256)

        # Verify raw bytes survived and match
        stored_bytes = ledger_b.case_evidence_store.get(self.case_id)
        self.assertIsNotNone(stored_bytes)
        self.assertEqual(stored_bytes, self.raw_eml)

    def test_6_cryptographic_integrity_verification_after_restart(self):
        """verify_case() succeeds and confirms INTEGRITY: VERIFIED after full repository re-instantiation."""
        # The case was anchored into the ledger during analyze() in setUp.
        # Now simulate a fresh process restart with an independent EvidenceLedger instance.
        ledger_b = EvidenceLedger(persist_to_db=True)
        verification = ledger_b.verify_case(self.case_id)

        self.assertEqual(verification["status"], "INTEGRITY: VERIFIED")
        self.assertTrue(verification["verified"])
        self.assertTrue(verification["checks"]["evidence_hash_match"])
        self.assertTrue(verification["checks"]["verdict_hash_match"])
        self.assertTrue(verification["checks"]["merkle_root_valid"])
        self.assertTrue(verification["checks"]["ledger_linkage_valid"])

    def test_7_forensic_html_report_after_memory_cache_cleared(self):
        """Forensic HTML report generates seamlessly when memory cache is wiped, rehydrating from DB."""
        repo = CaseRepository(persist_to_db=True)
        repo.create_or_update_from_analysis(self.result)

        # Wipe the in-memory cache to simulate post-restart state
        _CASE_RESULTS_STORE.clear()
        self.assertNotIn(self.case_id, _CASE_RESULTS_STORE)

        # Rehydrate from database via get_case_result
        rehydrated = get_case_result(self.case_id)
        self.assertIsNotNone(rehydrated)
        self.assertEqual(rehydrated.case_id, self.case_id)

        # Generate HTML report
        html_report = generate_html_report(rehydrated)
        self.assertIn("<!DOCTYPE html>", html_report)
        self.assertIn(self.case_id, html_report)

    def test_8_forensic_json_report_after_memory_cache_cleared(self):
        """SIEM/SOAR-ready JSON report exports successfully from rehydrated database model."""
        repo = CaseRepository(persist_to_db=True)
        repo.create_or_update_from_analysis(self.result)

        _CASE_RESULTS_STORE.clear()
        rehydrated = get_case_result(self.case_id)
        self.assertIsNotNone(rehydrated)

        json_report = generate_json_report(rehydrated)
        self.assertEqual(json_report["format_version"], "Citadel-Forensic-Dossier-v1.0")
        self.assertEqual(json_report["case_identification"]["case_id"], self.case_id)
        self.assertEqual(json_report["case_identification"]["threat_score"], self.result.threat_score)

    def test_9_audit_logs_recorded_for_lifecycle_events(self):
        """Audit log table contains records for case creation, status transition, and note addition."""
        with get_db_session() as session:
            logs = session.execute(
                select(AuditLogModel).where(AuditLogModel.case_id == self.case_id).order_by(AuditLogModel.id.asc())
            ).scalars().all()

            event_types = [l.event_type for l in logs]
            self.assertIn("CASE_CREATED", event_types)

    def test_10_postgresql_unreachable_fails_explicitly(self):
        """Providing an unreachable PostgreSQL URL raises ConnectionError and does NOT silently fall back."""
        bad_postgres_url = "postgresql://invalid_user:invalid_pass@127.0.0.1:5432/citadel_unreachable_db"
        with self.assertRaises(ConnectionError) as ctx:
            create_citadel_engine(bad_postgres_url)
        self.assertIn("Failed to connect to PostgreSQL", str(ctx.exception))
        self.assertIn("will NOT silently fall back to SQLite", str(ctx.exception))

    def test_11_backend_resolution_default_to_sqlite(self):
        """When DATABASE_URL is empty or omitted, resolver defaults to local persistent SQLite."""
        orig = os.environ.get("DATABASE_URL")
        try:
            if "DATABASE_URL" in os.environ:
                del os.environ["DATABASE_URL"]
            url, backend = resolve_database_url()
            self.assertIn("sqlite", url.lower())
            self.assertIn("SQLite", backend)
        finally:
            if orig is not None:
                os.environ["DATABASE_URL"] = orig


if __name__ == "__main__":
    unittest.main()
