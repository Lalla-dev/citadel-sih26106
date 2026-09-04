"""
Citadel Security Platform - Evidence & Risk Arbitration Test Suite
Validates:
1. Risk arbitration layer combining ML, authentication, URL/IOC, and behavioral pretexting.
2. Signal conflict moderation: ML threat + clean crypto auth -> GUARDED (30-49), not CRITICAL.
3. Signal conflict override: ML benign + DMARC failure / malicious URL -> Elevated risk.
4. Multi-vector corroboration: Spoofing + Reply-To diversion + Wire fraud -> CRITICAL (85-100).
5. Clean business email -> LOW (0-29).
6. Demo sample 'ambiguous_vendor_security_notice.eml' produces calibrated GUARDED score.
"""
import unittest
from pathlib import Path
from backend.parser import parse_eml
from backend.detector import CitadelDetectorOrchestrator

SAMPLES_DIR = Path(__file__).parent.parent / "samples"

class TestRiskArbitration(unittest.TestCase):
    def setUp(self):
        self.orchestrator = CitadelDetectorOrchestrator()

    def test_clean_email_calibrated_low(self):
        """Routine internal email with clean auth must score in LOW tier (0-29)."""
        eml_path = SAMPLES_DIR / "benign_project_update.eml"
        with open(eml_path, "rb") as f:
            parsed = parse_eml(f.read())
        res = self.orchestrator.analyze(parsed, filename="benign_project_update.eml")
        self.assertLess(res.threat_score, 30)
        self.assertEqual(res.risk_level, "LOW")
        self.assertIsNotNone(res.risk_arbitration)
        self.assertEqual(res.risk_arbitration.arbitration_status, "CONVERGENT")

    def test_ambiguous_vendor_advisory_calibrated_guarded(self):
        """Vendor security advisory with action required but valid auth should be GUARDED (30-49)."""
        eml_path = SAMPLES_DIR / "ambiguous_vendor_security_notice.eml"
        with open(eml_path, "rb") as f:
            parsed = parse_eml(f.read())
        res = self.orchestrator.analyze(parsed, filename="ambiguous_vendor_security_notice.eml")
        self.assertGreaterEqual(res.threat_score, 30)
        self.assertLessEqual(res.threat_score, 49)
        self.assertEqual(res.risk_level, "GUARDED")
        self.assertIsNotNone(res.risk_arbitration)
        self.assertEqual(res.risk_arbitration.arbitration_status, "SIGNAL_CONFLICT")

    def test_bogus_invoice_calibrated_high(self):
        """Invoice bank change with reply-to diversion and SPF softfail should be HIGH (70-84)."""
        eml_path = SAMPLES_DIR / "bec_invoice_bank_change.eml"
        with open(eml_path, "rb") as f:
            parsed = parse_eml(f.read())
        res = self.orchestrator.analyze(parsed, filename="bec_invoice_bank_change.eml")
        self.assertGreaterEqual(res.threat_score, 70)
        self.assertLessEqual(res.threat_score, 84)
        self.assertEqual(res.risk_level, "HIGH")

    def test_ceo_wire_fraud_calibrated_critical(self):
        """Executive impersonation wire fraud transfer should be CRITICAL (85-100)."""
        eml_path = SAMPLES_DIR / "bec_ceo_wire_fraud.eml"
        with open(eml_path, "rb") as f:
            parsed = parse_eml(f.read())
        res = self.orchestrator.analyze(parsed, filename="bec_ceo_wire_fraud.eml")
        self.assertGreaterEqual(res.threat_score, 85)
        self.assertLessEqual(res.threat_score, 100)
        self.assertEqual(res.risk_level, "CRITICAL")
        self.assertEqual(res.risk_arbitration.arbitration_status, "CONVERGENT")

    def test_credential_phishing_link_calibrated_critical(self):
        """DMARC failure + raw IP URL + urgent account suspension should be CRITICAL (85-100)."""
        eml_path = SAMPLES_DIR / "credential_phishing_link.eml"
        with open(eml_path, "rb") as f:
            parsed = parse_eml(f.read())
        res = self.orchestrator.analyze(parsed, filename="credential_phishing_link.eml")
        self.assertGreaterEqual(res.threat_score, 85)
        self.assertLessEqual(res.threat_score, 100)
        self.assertEqual(res.risk_level, "CRITICAL")
        self.assertEqual(res.risk_arbitration.arbitration_status, "CONVERGENT")

    def test_signal_conflict_override_when_dmarc_fails(self):
        """Objective security failure (DMARC fail) must override benign text and elevate risk."""
        raw_eml = (
            "From: notifications@service.com\n"
            "To: user@company.com\n"
            "Subject: Your statement is ready\n"
            "Authentication-Results: mx.company.com; spf=fail smtp.mailfrom=bad.net; dkim=fail; dmarc=fail\n"
            "Content-Type: text/plain; charset=utf-8\n\n"
            "Hello, your monthly statement is available for review."
        )
        parsed = parse_eml(raw_eml)
        res = self.orchestrator.analyze(parsed, filename="dmarc_fail.eml")
        # Must not be LOW due to DMARC failure
        self.assertGreaterEqual(res.threat_score, 50)
        self.assertIn(res.risk_level, ["MEDIUM", "HIGH", "CRITICAL"])

if __name__ == "__main__":
    unittest.main()
