"""
Citadel Security Platform - Robustness, Edge Cases & Threat Scoring Review Test Suite
Validates:
1. Plain-text only emails.
2. HTML-only emails.
3. Multipart emails.
4. Missing optional headers (no Subject, From, To, Date, etc.).
5. Malformed/corrupted headers and unresolvable charsets.
6. Email with multiple URLs (15+ URLs) and zero URLs.
7. Single-indicator scoring calibration (preventing single cues from inflating score).
8. Repeated identical uploads and Case ID continuity.
"""
import unittest
from backend.parser import parse_eml
from backend.headers import analyze_headers
from backend.url_analyzer import analyze_urls
from backend.detector import CitadelDetectorOrchestrator

class TestRobustnessAndEdgeCases(unittest.TestCase):
    def setUp(self):
        self.orchestrator = CitadelDetectorOrchestrator()

    def test_plain_text_only_email(self):
        raw_eml = (
            "From: alice@internal.net\n"
            "To: bob@internal.net\n"
            "Subject: Routine meeting\n"
            "Content-Type: text/plain; charset=utf-8\n\n"
            "Hey Bob, see you at 2pm."
        )
        parsed = parse_eml(raw_eml)
        result = self.orchestrator.analyze(parsed, filename="plain_text.eml")
        self.assertEqual(result.metadata.subject, "Routine meeting")
        self.assertEqual(result.body_text_preview, "Hey Bob, see you at 2pm.")
        self.assertEqual(len(result.urls), 0)
        self.assertEqual(result.risk_level, "LOW")

    def test_html_only_email(self):
        raw_eml = (
            "From: notifications@service.com\n"
            "To: user@service.com\n"
            "Subject: HTML Notice\n"
            "Content-Type: text/html; charset=utf-8\n\n"
            "<html><body><h1>Hello</h1><p>Your statement is ready at <a href='https://service.com/account'>portal</a></p></body></html>"
        )
        parsed = parse_eml(raw_eml)
        result = self.orchestrator.analyze(parsed, filename="html_only.eml")
        self.assertEqual(result.metadata.subject, "HTML Notice")
        self.assertIn("https://service.com/account", [u.url for u in result.urls])
        self.assertEqual(result.risk_level, "LOW")

    def test_multipart_email(self):
        boundary = "====BOUNDARY_12345===="
        raw_eml = (
            f"From: sender@corp.com\n"
            f"To: receiver@corp.com\n"
            f"Subject: Multipart Test\n"
            f"MIME-Version: 1.0\n"
            f"Content-Type: multipart/alternative; boundary=\"{boundary}\"\n\n"
            f"--{boundary}\n"
            f"Content-Type: text/plain; charset=utf-8\n\n"
            f"Plain text view.\n\n"
            f"--{boundary}\n"
            f"Content-Type: text/html; charset=utf-8\n\n"
            f"<html><body>HTML view with <a href='https://example.com/link'>Link</a></body></html>\n\n"
            f"--{boundary}--\n"
        )
        parsed = parse_eml(raw_eml)
        result = self.orchestrator.analyze(parsed, filename="multipart.eml")
        self.assertEqual(result.metadata.subject, "Multipart Test")
        self.assertEqual(len(result.urls), 1)
        self.assertEqual(result.urls[0].url, "https://example.com/link")

    def test_missing_optional_headers(self):
        # Email with absolutely no headers except body
        raw_eml = "Just a stray raw body with no headers at all."
        parsed = parse_eml(raw_eml)
        result = self.orchestrator.analyze(parsed, filename="no_headers.eml")
        self.assertTrue(result.case_id.startswith("CASE-2026-"))
        self.assertEqual(result.metadata.subject, "")
        self.assertEqual(result.metadata.sender_email, "")
        self.assertEqual(result.risk_level, "LOW")

    def test_malformed_headers_and_unknown_charset(self):
        # Email with unknown charset and corrupted characters
        raw_eml = (
            "From: =?invalid-charset?B?99999?=\n"
            "Subject: \x00\x01\x02 Corrupted Bytes\n"
            "Content-Type: text/plain; charset=\"unknown-cp-999\"\n"
            "Authentication-Results: ;;;;;garbled text====\n\n"
            "Body with unprintable \x00\x01\x02 bytes"
        )
        parsed = parse_eml(raw_eml)
        # Verify parser does not throw
        result = self.orchestrator.analyze(parsed, filename="corrupted.eml")
        self.assertIsNotNone(result)
        self.assertTrue(result.case_id.startswith("CASE-2026-"))

    def test_multiple_urls(self):
        urls = [f"https://sub{i}.company.com/page{i}?param={i}" for i in range(15)]
        body = "Multiple links:\n" + "\n".join(urls)
        raw_eml = (
            "From: webmaster@company.com\n"
            "To: team@company.com\n"
            "Subject: 15 Links Digest\n"
            "Content-Type: text/plain; charset=utf-8\n\n"
            f"{body}"
        )
        parsed = parse_eml(raw_eml)
        result = self.orchestrator.analyze(parsed, filename="multi_urls.eml")
        self.assertGreaterEqual(len(result.urls), 15)
        # Since all URLs are standard subdomains on company.com, risk should remain manageable
        # (Phase 2+ ML and enrichment may add minor boost, so threshold accounts for multi-signal layers)
        self.assertLessEqual(result.threat_score, 50)

    def test_zero_urls(self):
        raw_eml = (
            "From: hr@acme.com\n"
            "To: all@acme.com\n"
            "Subject: Annual Holiday Party\n"
            "Content-Type: text/plain; charset=utf-8\n\n"
            "Join us in the lobby this Friday at 5 PM for treats and refreshments."
        )
        parsed = parse_eml(raw_eml)
        result = self.orchestrator.analyze(parsed, filename="no_urls.eml")
        self.assertEqual(len(result.urls), 0)
        self.assertEqual(result.threat_score, 0)
        self.assertEqual(result.risk_level, "LOW")

    def test_single_suspicious_indicator_does_not_overinflate(self):
        """
        Critical Rule: A single isolated trigger (e.g. single urgency word or SPF neutral)
        must NEVER cause an unjustifiably high score (score >= 45) or False Critical.
        """
        # Scenario A: Email with just one urgency word in a normal conversation
        raw_urgency_only = (
            "From: colleague@acme.internal\n"
            "To: developer@acme.internal\n"
            "Subject: Quick question asap\n"
            "Authentication-Results: mx.acme.internal; spf=pass; dkim=pass; dmarc=pass\n"
            "Content-Type: text/plain; charset=utf-8\n\n"
            "Could you reply asap with the build number?"
        )
        parsed_a = parse_eml(raw_urgency_only)
        result_a = self.orchestrator.analyze(parsed_a)
        # Score must be LOW, not jumping to HIGH or CRITICAL
        self.assertLessEqual(result_a.threat_score, 25)
        self.assertEqual(result_a.risk_level, "LOW")

        # Scenario B: Email with same-domain Reply-To routing
        raw_alias_only = (
            "From: newsletter@company.com\n"
            "Reply-To: support@company.com\n"
            "To: user@client.com\n"
            "Subject: Weekly News\n"
            "Authentication-Results: mx.client.com; spf=pass; dkim=pass; dmarc=pass\n"
            "Content-Type: text/plain; charset=utf-8\n\n"
            "Here is your weekly digest."
        )
        parsed_b = parse_eml(raw_alias_only)
        result_b = self.orchestrator.analyze(parsed_b)
        self.assertFalse(result_b.authentication.reply_to_mismatch)
        self.assertLessEqual(result_b.threat_score, 15)
        self.assertEqual(result_b.risk_level, "LOW")

    def test_repeated_uploads_case_id_continuity(self):
        """Verify uploading the same email repeatedly produces incrementing unique case IDs without crashing."""
        raw_eml = (
            "From: user@acme.internal\n"
            "To: dev@acme.internal\n"
            "Subject: Continuity Check\n"
            "Content-Type: text/plain; charset=utf-8\n\n"
            "Testing case IDs."
        )
        case_ids = []
        for i in range(5):
            parsed = parse_eml(raw_eml)
            res = self.orchestrator.analyze(parsed, filename=f"test_run_{i}.eml")
            case_ids.append(res.case_id)

        # All case IDs must be distinct and follow CASE-2026-XXXX format
        self.assertEqual(len(set(case_ids)), 5)
        for cid in case_ids:
            self.assertTrue(cid.startswith("CASE-2026-"))

if __name__ == "__main__":
    unittest.main()
