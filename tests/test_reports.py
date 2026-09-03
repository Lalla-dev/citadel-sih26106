"""
Citadel Phase 8 Tests - Forensic Incident Reporting & Dossier Export
Tests printable HTML dossier generation, SIEM/SOAR structured JSON export,
presence of all forensic sections, and API endpoints.
"""
import unittest
import json
from fastapi.testclient import TestClient

from backend.main import app
from backend.parser import parse_eml
from backend.detector import CitadelDetectorOrchestrator
from backend.schemas import AnalysisResult, URLAnalysis
from backend.reports import (
    generate_html_report,
    generate_json_report,
    generate_executive_summary,
    store_case_result,
    get_case_result
)


class TestForensicReportingEngine(unittest.TestCase):
    """Unit tests for Phase 8 reporting generator and schemas."""

    def setUp(self):
        self.orchestrator = CitadelDetectorOrchestrator()
        raw_eml = (
            b"From: \"CEO John\" <attacker@spoofed-ceo.com>\r\n"
            b"To: finance@corp.com\r\n"
            b"Subject: Urgent Wire Transfer Required Immediately\r\n"
            b"Date: Mon, 1 Sep 2026 10:00:00 +0000\r\n"
            b"Message-ID: <msg-12345@spoofed.com>\r\n"
            b"Received-SPF: softfail\r\n"
            b"\r\n"
            b"Please send $45,000 immediately to account 987654321. Do not call, I am in meetings. "
            b"Verify invoice details at http://198.51.100.44/invoice.pdf"
        )
        parsed = parse_eml(raw_eml)
        self.result = self.orchestrator.analyze(parsed, filename="wire_transfer.eml", raw_bytes=raw_eml)
        store_case_result(self.result)

    def test_1_report_generation_for_valid_case(self):
        """Report generation succeeds and returns a non-empty HTML string."""
        html = generate_html_report(self.result)
        self.assertIsInstance(html, str)
        self.assertGreater(len(html), 500)
        self.assertIn("<!DOCTYPE html>", html)

    def test_2_report_contains_case_id(self):
        """HTML dossier and JSON export contain the correct Case ID."""
        html = generate_html_report(self.result)
        self.assertIn(self.result.case_id, html)

        json_data = generate_json_report(self.result)
        self.assertEqual(json_data["case_identification"]["case_id"], self.result.case_id)

    def test_3_report_contains_threat_score_risk_archetype(self):
        """HTML dossier contains threat score, risk level, and archetype."""
        html = generate_html_report(self.result)
        self.assertIn(f"{self.result.threat_score}/100", html)
        self.assertIn(self.result.risk_level, html)
        self.assertIn(self.result.threat_archetype, html)

    def test_4_report_contains_email_header_information(self):
        """HTML report contains subject, sender, recipient, and date."""
        html = generate_html_report(self.result)
        self.assertIn(self.result.metadata.subject, html)
        self.assertIn(self.result.metadata.sender_email, html)
        self.assertIn(self.result.metadata.recipient, html)

    def test_5_report_contains_authentication_results(self):
        """HTML report contains parsed SPF/DKIM/DMARC and static parsing disclaimer."""
        html = generate_html_report(self.result)
        self.assertIn("SPF (Parsed)", html)
        self.assertIn("DKIM (Parsed)", html)
        self.assertIn("DMARC (Parsed)", html)
        self.assertIn("static header parsing only", html.lower())

    def test_6_report_contains_url_ioc_information_when_available(self):
        """HTML report and JSON include extracted URL, domain, and entropy."""
        html = generate_html_report(self.result)
        self.assertIn("198.51.100.44", html)

        json_data = generate_json_report(self.result)
        self.assertGreater(json_data["url_ioc_analysis"]["url_count"], 0)
        self.assertEqual(json_data["url_ioc_analysis"]["urls"][0]["domain"], "198.51.100.44")

    def test_7_report_contains_ml_and_nlp_information(self):
        """HTML report includes ML classification and Contextual NLP pretexting."""
        html = generate_html_report(self.result)
        self.assertIn("TF-IDF + Logistic Regression", html)
        self.assertIn("Semantic Pretexting", html)
        self.assertIn(self.result.ml_classification.predicted_label.upper(), html)

    def test_8_report_contains_phase_9_evidence_hashes(self):
        """HTML report incorporates Phase 9 raw evidence SHA-256 and verdict digest."""
        html = generate_html_report(self.result)
        self.assertIsNotNone(self.result.integrity)
        self.assertIn(self.result.integrity.evidence_sha256, html)
        self.assertIn(self.result.integrity.verdict_sha256, html)

    def test_9_report_contains_integrity_status(self):
        """HTML report explicitly states the cryptographic integrity status."""
        html = generate_html_report(self.result)
        self.assertIn("INTEGRITY: VERIFIED", html)

    def test_10_json_export_is_valid_json(self):
        """JSON export serializes to valid RFC 8259 JSON format."""
        json_data = generate_json_report(self.result)
        serialized = json.dumps(json_data)
        deserialized = json.loads(serialized)
        self.assertEqual(deserialized["format_version"], "Citadel-Forensic-Dossier-v1.0")

    def test_11_json_export_contains_expected_forensic_fields(self):
        """JSON export contains all required SOC forensic sections."""
        json_data = generate_json_report(self.result)
        required_keys = [
            "format_version", "export_type", "export_timestamp", "case_identification",
            "executive_summary", "email_forensics", "authentication_analysis",
            "url_ioc_analysis", "ml_nlp_analysis", "threat_intelligence_enrichment",
            "correlation_graph_summary", "evidence_integrity", "detection_reasoning",
            "recommended_soc_actions"
        ]
        for key in required_keys:
            self.assertIn(key, json_data)

    def test_12_missing_optional_fields_do_not_crash_report_generation(self):
        """Report generator handles empty or minimal AnalysisResult without crashing."""
        minimal_result = AnalysisResult(
            case_id="CASE-MINIMAL-001",
            threat_score=0,
            risk_level="LOW",
            threat_archetype="Clean Email"
        )
        # HTML rendering must not raise an exception
        html = generate_html_report(minimal_result)
        self.assertIn("CASE-MINIMAL-001", html)

        # JSON export must not raise an exception
        json_data = generate_json_report(minimal_result)
        self.assertEqual(json_data["case_identification"]["case_id"], "CASE-MINIMAL-001")


class TestForensicReportAPIEndpoints(unittest.TestCase):
    """Integration tests for report REST API endpoints."""

    def setUp(self):
        self.client = TestClient(app)
        # Pre-populate by analyzing a sample email
        resp = self.client.get("/api/sample/credential_phishing_link.eml")
        self.case_id = resp.json()["case_id"]

    def test_get_report_html_endpoint(self):
        """GET /api/case/{case_id}/report returns 200 OK with HTML content."""
        resp = self.client.get(f"/api/case/{self.case_id}/report")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/html", resp.headers["content-type"])
        self.assertIn("FORENSIC INCIDENT DOSSIER", resp.text)
        self.assertIn("CITADEL", resp.text)

    def test_get_report_json_endpoint(self):
        """GET /api/case/{case_id}/report/json returns 200 OK with structured JSON."""
        resp = self.client.get(f"/api/case/{self.case_id}/report/json")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("application/json", resp.headers["content-type"])
        data = resp.json()
        self.assertEqual(data["case_identification"]["case_id"], self.case_id)
        self.assertIn("executive_summary", data)
        self.assertIn("url_ioc_analysis", data)

    def test_nonexistent_case_returns_404(self):
        """GET for unknown case_id returns 404."""
        resp = self.client.get("/api/case/CASE-UNKNOWN-9999/report")
        self.assertEqual(resp.status_code, 404)

        resp_json = self.client.get("/api/case/CASE-UNKNOWN-9999/report/json")
        self.assertEqual(resp_json.status_code, 404)


if __name__ == "__main__":
    unittest.main()
