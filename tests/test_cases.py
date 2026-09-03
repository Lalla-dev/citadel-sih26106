"""
Citadel Phase 7 Tests - SOC Case Management & Incident Triage Engine
Tests ticket lifecycle transitions, analyst notes, queue filtering,
and case management REST API endpoints.
"""
import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.parser import parse_eml
from backend.detector import CitadelDetectorOrchestrator
from backend.cases import CaseRepository, CaseTicket, VALID_STATUSES


class TestCaseManagementRepository(unittest.TestCase):
    """Unit tests for CaseRepository and CaseTicket lifecycle logic."""

    def setUp(self):
        self.repo = CaseRepository()
        self.orchestrator = CitadelDetectorOrchestrator()

        # Generate two sample analysis results
        raw1 = (
            b"From: ceo@phish.com\r\n"
            b"To: accountant@company.com\r\n"
            b"Subject: Immediate Wire Needed\r\n\r\n"
            b"Transfer $50,000 to vendor immediately."
        )
        parsed1 = parse_eml(raw1)
        self.res1 = self.orchestrator.analyze(parsed1, filename="ceo_wire.eml", raw_bytes=raw1)

        raw2 = (
            b"From: updates@github.com\r\n"
            b"To: dev@company.com\r\n"
            b"Subject: Weekly Project Status\r\n\r\n"
            b"Sprint review scheduled for tomorrow."
        )
        parsed2 = parse_eml(raw2)
        self.res2 = self.orchestrator.analyze(parsed2, filename="update.eml", raw_bytes=raw2)

    def test_1_create_case_ticket_from_analysis(self):
        """Creating ticket from AnalysisResult populates all required fields."""
        ticket = self.repo.create_or_update_from_analysis(self.res1)
        self.assertEqual(ticket.case_id, self.res1.case_id)
        self.assertEqual(ticket.threat_score, self.res1.threat_score)
        self.assertEqual(ticket.risk_level, self.res1.risk_level)
        self.assertEqual(ticket.status, "NEW")
        self.assertEqual(ticket.assigned_analyst, "Unassigned")
        self.assertEqual(len(ticket.notes), 0)

    def test_2_list_cases_sorted_newest_first(self):
        """Listing cases returns all tickets in reverse chronological order."""
        t1 = self.repo.create_or_update_from_analysis(self.res1)
        t2 = self.repo.create_or_update_from_analysis(self.res2)

        cases = self.repo.list_cases()
        self.assertEqual(len(cases), 2)
        self.assertEqual(cases[0].case_id, t2.case_id)

    def test_3_status_lifecycle_transition(self):
        """Valid lifecycle transitions update status and record an audit note."""
        ticket = self.repo.create_or_update_from_analysis(self.res1)
        
        # Transition: NEW -> INVESTIGATING
        updated = self.repo.update_status(ticket.case_id, "INVESTIGATING", analyst="Tier-1 Analyst")
        self.assertEqual(updated.status, "INVESTIGATING")
        self.assertEqual(updated.assigned_analyst, "Tier-1 Analyst")
        self.assertEqual(len(updated.notes), 1)
        self.assertIn("Status transitioned from NEW to INVESTIGATING", updated.notes[0].note)

        # Transition: INVESTIGATING -> CONTAINED
        updated2 = self.repo.update_status(ticket.case_id, "CONTAINED")
        self.assertEqual(updated2.status, "CONTAINED")
        self.assertEqual(len(updated2.notes), 2)

    def test_4_invalid_status_raises_value_error(self):
        """Invalid lifecycle state raises ValueError."""
        ticket = self.repo.create_or_update_from_analysis(self.res1)
        with self.assertRaises(ValueError):
            self.repo.update_status(ticket.case_id, "INVALID_STATE_XYZ")

    def test_5_add_analyst_investigation_note(self):
        """Analyst can append timestamped notes to the case ticket."""
        ticket = self.repo.create_or_update_from_analysis(self.res1)
        self.repo.add_note(ticket.case_id, "Quarantined email on Exchange gateway.", author="Jane Doe (SecOps)")

        updated = self.repo.get_case(ticket.case_id)
        self.assertEqual(len(updated.notes), 1)
        self.assertEqual(updated.notes[0].author, "Jane Doe (SecOps)")
        self.assertEqual(updated.notes[0].note, "Quarantined email on Exchange gateway.")

    def test_6_filter_cases_by_status(self):
        """Filtering by status returns only matching tickets."""
        self.repo.create_or_update_from_analysis(self.res1)
        t2 = self.repo.create_or_update_from_analysis(self.res2)
        self.repo.update_status(t2.case_id, "RESOLVED")

        new_cases = self.repo.list_cases(status="NEW")
        self.assertEqual(len(new_cases), 1)
        self.assertEqual(new_cases[0].case_id, self.res1.case_id)

        resolved_cases = self.repo.list_cases(status="RESOLVED")
        self.assertEqual(len(resolved_cases), 1)
        self.assertEqual(resolved_cases[0].case_id, t2.case_id)

    def test_7_filter_cases_by_risk_level(self):
        """Filtering by risk level works accurately."""
        self.repo.create_or_update_from_analysis(self.res1)
        self.repo.create_or_update_from_analysis(self.res2)

        crit_cases = self.repo.list_cases(risk_level=self.res1.risk_level)
        self.assertGreaterEqual(len(crit_cases), 1)

    def test_8_search_cases_by_query(self):
        """Search filters by case_id, subject, or sender."""
        self.repo.create_or_update_from_analysis(self.res1)
        self.repo.create_or_update_from_analysis(self.res2)

        wire_matches = self.repo.list_cases(search="Wire")
        self.assertEqual(len(wire_matches), 1)
        self.assertEqual(wire_matches[0].case_id, self.res1.case_id)

        github_matches = self.repo.list_cases(search="github.com")
        self.assertEqual(len(github_matches), 1)
        self.assertEqual(github_matches[0].case_id, self.res2.case_id)

    def test_9_queue_statistics(self):
        """Queue stats aggregate total, risk, and status distributions."""
        self.repo.create_or_update_from_analysis(self.res1)
        t2 = self.repo.create_or_update_from_analysis(self.res2)
        self.repo.update_status(t2.case_id, "CONTAINED")

        stats = self.repo.get_queue_statistics()
        self.assertEqual(stats["total_cases"], 2)
        self.assertEqual(stats["contained_resolved"], 1)
        self.assertIn("NEW", stats["by_status"])


class TestCaseManagementAPI(unittest.TestCase):
    """Integration tests for Phase 7 REST API endpoints."""

    def setUp(self):
        self.client = TestClient(app)
        # Pre-populate by analyzing sample email
        resp = self.client.get("/api/sample/credential_phishing_link.eml")
        self.case_id = resp.json()["case_id"]

    def test_get_cases_queue_endpoint(self):
        """GET /api/cases returns list of cases and queue stats."""
        resp = self.client.get("/api/cases")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("cases", data)
        self.assertIn("stats", data)
        self.assertGreaterEqual(data["count"], 1)
        self.assertTrue(any(c["case_id"] == self.case_id for c in data["cases"]))

    def test_get_case_details_endpoint(self):
        """GET /api/cases/{id} returns ticket details with analysis result."""
        resp = self.client.get(f"/api/cases/{self.case_id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["case_id"], self.case_id)
        self.assertIn("analysis_result", data)

    def test_patch_case_status_endpoint(self):
        """PATCH /api/cases/{id}/status updates lifecycle status."""
        resp = self.client.patch(
            f"/api/cases/{self.case_id}/status",
            json={"status": "INVESTIGATING", "analyst": "SOC Lead"}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "INVESTIGATING")
        self.assertEqual(data["assigned_analyst"], "SOC Lead")

    def test_add_case_note_endpoint(self):
        """POST /api/cases/{id}/notes appends analyst note."""
        resp = self.client.post(
            f"/api/cases/{self.case_id}/notes",
            json={"note": "Blocked sender domain on firewall.", "author": "Analyst 42"}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(any(n["note"] == "Blocked sender domain on firewall." for n in data["notes"]))

    def test_nonexistent_case_returns_404(self):
        """Unknown case returns 404 for get, patch status, and add note."""
        resp = self.client.get("/api/cases/CASE-FAKE-9999")
        self.assertEqual(resp.status_code, 404)

        resp2 = self.client.patch("/api/cases/CASE-FAKE-9999/status", json={"status": "CONTAINED"})
        self.assertEqual(resp2.status_code, 404)

        resp3 = self.client.post("/api/cases/CASE-FAKE-9999/notes", json={"note": "Test note"})
        self.assertEqual(resp3.status_code, 404)


if __name__ == "__main__":
    unittest.main()
