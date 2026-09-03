"""
Citadel Security Platform - Pipeline Automated Test Suite
Tests email parsing, header authentication, URL feature extraction,
and BEC/phishing scoring across benign and malicious test samples.
"""
import os
import unittest
from pathlib import Path
from backend.parser import parse_eml
from backend.headers import analyze_headers
from backend.url_analyzer import calculate_shannon_entropy, analyze_single_url, analyze_urls
from backend.detector import CitadelDetectorOrchestrator, HeuristicRuleDetector

SAMPLES_DIR = Path(__file__).parent.parent / "samples"

class TestCitadelPipeline(unittest.TestCase):
    def setUp(self):
        self.orchestrator = CitadelDetectorOrchestrator()

    def test_shannon_entropy_calculation(self):
        # High randomness / token padding should have higher entropy than simple repetitive strings
        low_ent = calculate_shannon_entropy("aaaaaaaabbbbbbbb")
        self.assertEqual(low_ent, 1.0)
        
        url = "http://198.51.100.44/portal/login-secure-update?token=a8f93e1b7c2d84%2Fverify%3Dauth&sess=98213894723947239"
        high_ent = calculate_shannon_entropy(url)
        self.assertGreaterEqual(high_ent, 4.0)

    def test_url_analyzer_obfuscation(self):
        malicious_url = "http://198.51.100.44/portal/login-secure-update?token=a8f93e1b7c2d84%2Fverify%3Dauth"
        analysis = analyze_single_url(malicious_url)
        self.assertTrue(analysis.is_ip_address)
        self.assertTrue(analysis.has_hex_encoding)
        self.assertTrue(analysis.has_deceptive_keywords)
        self.assertEqual(analysis.risk_category, "MALICIOUS")
        self.assertGreaterEqual(analysis.risk_score, 60.0)

        clean_url = "https://portal.acme-corp.internal/jira/projects/NEXUS"
        clean_analysis = analyze_single_url(clean_url)
        self.assertFalse(clean_analysis.is_ip_address)
        self.assertEqual(clean_analysis.risk_category, "SAFE")

    def test_benign_email_analysis(self):
        file_path = SAMPLES_DIR / "benign_project_update.eml"
        with open(file_path, "rb") as f:
            parsed = parse_eml(f.read())
        
        result = self.orchestrator.analyze(parsed, filename="benign_project_update.eml")
        
        self.assertTrue(result.case_id.startswith("CASE-2026-"))
        self.assertEqual(result.filename, "benign_project_update.eml")
        self.assertLessEqual(result.threat_score, 20)
        self.assertEqual(result.risk_level, "LOW")
        self.assertEqual(result.threat_archetype, "Clean Email")
        self.assertFalse(result.authentication.live_verified)
        self.assertIn("Static RFC 5322", result.authentication.verification_method)
        self.assertEqual(result.authentication.spf.status, "pass")
        self.assertEqual(result.authentication.dkim.status, "pass")

    def test_credential_phishing_analysis(self):
        file_path = SAMPLES_DIR / "credential_phishing_link.eml"
        with open(file_path, "rb") as f:
            parsed = parse_eml(f.read())
        
        result = self.orchestrator.analyze(parsed, filename="credential_phishing_link.eml")
        
        self.assertGreaterEqual(result.threat_score, 70)
        self.assertIn(result.risk_level, ["HIGH", "CRITICAL"])
        self.assertEqual(result.threat_archetype, "Credential Phishing")
        self.assertGreaterEqual(result.confidence, 0.70)
        self.assertTrue(result.intent.urgency_detected)
        self.assertGreaterEqual(len(result.urls), 1)
        self.assertEqual(result.urls[0].risk_category, "MALICIOUS")
        self.assertTrue(any("credentials" in r.description or "Malicious link" in r.description for r in result.reasons))

    def test_bec_ceo_fraud_analysis(self):
        file_path = SAMPLES_DIR / "bec_ceo_wire_fraud.eml"
        with open(file_path, "rb") as f:
            parsed = parse_eml(f.read())
        
        result = self.orchestrator.analyze(parsed, filename="bec_ceo_wire_fraud.eml")
        
        self.assertGreaterEqual(result.threat_score, 70)
        self.assertEqual(result.threat_archetype, "CEO Fraud / Executive Spoofing")
        self.assertTrue(result.authentication.display_name_spoofed)
        self.assertTrue(result.authentication.reply_to_mismatch)
        self.assertTrue(result.intent.financial_wire_detected)
        self.assertTrue(result.intent.authority_pretext_detected)
        self.assertGreaterEqual(result.confidence, 0.80)
        self.assertTrue(any("HALT any payment" in a for a in result.recommended_actions))

    def test_bec_invoice_bank_change_analysis(self):
        file_path = SAMPLES_DIR / "bec_invoice_bank_change.eml"
        with open(file_path, "rb") as f:
            parsed = parse_eml(f.read())
        
        result = self.orchestrator.analyze(parsed, filename="bec_invoice_bank_change.eml")
        
        self.assertGreaterEqual(result.threat_score, 50)
        self.assertEqual(result.threat_archetype, "Bogus Invoice / Banking Redirection")
        self.assertTrue(result.intent.financial_wire_detected)
        self.assertIn("routing number", result.intent.financial_keywords)
        self.assertTrue(any("two-party procedural verification" in a for a in result.recommended_actions))

if __name__ == "__main__":
    unittest.main()
