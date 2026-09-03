"""
Citadel Phase 4 Tests - Contextual NLP & Intent Pretexting Engine
Tests semantic archetype alignment, psychological coercion scoring, and pipeline integration.
"""
import unittest
from backend.nlp import ContextualNLPEngine, get_nlp_engine
from backend.parser import parse_eml
from backend.detector import CitadelDetectorOrchestrator
from fastapi.testclient import TestClient
from backend.main import app


class TestContextualNLP(unittest.TestCase):
    """Test standalone Contextual NLP Pretexting Engine."""

    def setUp(self):
        self.engine = get_nlp_engine()

    def test_ceo_fraud_semantic_alignment(self):
        """Should detect CEO Fraud pretext and authority/confidentiality markers."""
        subject = "Strictly Confidential - Immediate Action Required"
        body = (
            "I am currently in a board meeting and cannot take calls. "
            "We are closing a confidential acquisition today. "
            "Please wire $150,000 immediately to the escrow account and keep this private."
        )
        res = self.engine.analyze_context(subject, body)
        self.assertEqual(res["dominant_archetype"], "CEO_FRAUD_PRETEXT")
        self.assertGreater(res["archetype_similarities"]["CEO_FRAUD_PRETEXT"], 0.2)
        self.assertIn(res["coercion_level"], ["HIGH", "CRITICAL"])
        self.assertIn("Executive", res["tone"])

    def test_invoice_fraud_semantic_alignment(self):
        """Should detect vendor invoice / banking alteration pretext."""
        subject = "Updated Remittance and Banking Details for Overdue Invoice"
        body = (
            "Please note that our direct deposit instructions and vendor payment details have changed. "
            "Update our banking details to the new ACH routing number before processing the invoice."
        )
        res = self.engine.analyze_context(subject, body)
        self.assertEqual(res["dominant_archetype"], "INVOICE_FRAUD_PRETEXT")
        self.assertGreater(res["archetype_similarities"]["INVOICE_FRAUD_PRETEXT"], 0.2)
        self.assertIn("Transactional", res["tone"])

    def test_credential_phish_semantic_alignment(self):
        """Should detect credential harvest and punitive urgency pretext."""
        subject = "URGENT: Security Alert - Account Suspended"
        body = (
            "Your password will expire within 24 hours due to unauthorized login activity. "
            "Click here to verify your credentials immediately or your account will be terminated."
        )
        res = self.engine.analyze_context(subject, body)
        self.assertEqual(res["dominant_archetype"], "CREDENTIAL_HARVEST_PRETEXT")
        self.assertGreater(res["coercion_score"], 0.3)

    def test_benign_internal_collaboration(self):
        """Clean project sync should align to BENIGN_COLLABORATION with low coercion."""
        subject = "Sprint Planning Notes & Calendar Invite"
        body = (
            "Hi team, attached are the meeting agenda notes from our sprint review. "
            "Let me know your thoughts before our standup tomorrow. Thanks everyone!"
        )
        res = self.engine.analyze_context(subject, body)
        self.assertEqual(res["dominant_archetype"], "BENIGN_COLLABORATION")
        self.assertEqual(res["coercion_level"], "LOW")
        self.assertLess(res["coercion_score"], 0.2)


class TestNLPPipelineIntegration(unittest.TestCase):
    """Test NLP integration into the end-to-end analysis orchestrator."""

    def setUp(self):
        self.orchestrator = CitadelDetectorOrchestrator()

    def test_analysis_result_contains_nlp(self):
        """Verify AnalysisResult includes populated nlp_analysis."""
        eml = (
            "From: ceo@corp-exec.com\r\n"
            "To: finance@corp.com\r\n"
            "Subject: Urgent Confidential Transfer\r\n\r\n"
            "I need you to process an immediate wire transfer for our acquisition. Keep this confidential.\r\n"
        ).encode()
        parsed = parse_eml(eml)
        result = self.orchestrator.analyze(parsed, "ceo.eml")

        self.assertTrue(hasattr(result, "nlp_analysis"))
        self.assertIsNotNone(result.nlp_analysis)
        self.assertEqual(result.nlp_analysis.dominant_archetype, "CEO_FRAUD_PRETEXT")
        # Check that NLP reason was recorded
        nlp_reasons = [r for r in result.reasons if r.category in ("Contextual NLP", "Social Engineering")]
        self.assertGreater(len(nlp_reasons), 0)


if __name__ == "__main__":
    unittest.main()
