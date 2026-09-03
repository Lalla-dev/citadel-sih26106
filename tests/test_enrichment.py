"""
Citadel Phase 3 Tests - DNS & Domain Intelligence Enrichment
Tests domain reputation analysis, DNS resolution, and pipeline integration.
"""
import unittest
from backend.enrichment import (
    analyze_domain_reputation,
    extract_domain,
    get_tld,
    enrich_sender_domain,
)
from backend.parser import parse_eml
from backend.detector import CitadelDetectorOrchestrator
from fastapi.testclient import TestClient
from backend.main import app


class TestDomainReputationAnalysis(unittest.TestCase):
    """Test domain reputation heuristic analysis."""

    def test_known_legitimate_domain(self):
        """Known legitimate domains should score high reputation."""
        result = analyze_domain_reputation("google.com")
        self.assertTrue(result["is_known_legitimate"])
        self.assertEqual(result["reputation_label"], "TRUSTED")
        self.assertGreaterEqual(result["reputation_score"], 75)

    def test_suspicious_tld(self):
        """Domains with suspicious TLDs should be penalized."""
        result = analyze_domain_reputation("randomsite.xyz")
        self.assertTrue(result["tld_suspicious"])
        self.assertLess(result["reputation_score"], 50)

    def test_brand_impersonation_detection(self):
        """Domains containing brand names but not official should be flagged."""
        result = analyze_domain_reputation("microsoft-security-update.com")
        self.assertTrue(result["brand_impersonation"])
        self.assertEqual(result["impersonated_brand"], "microsoft")

    def test_excessive_subdomains(self):
        """Excessive subdomain depth should reduce reputation."""
        result = analyze_domain_reputation("login.verify.secure.bank.example.xyz")
        self.assertGreater(result["subdomain_depth"], 2)
        self.assertIn("subdomain depth", " ".join(result["signals"]).lower())

    def test_empty_domain(self):
        result = analyze_domain_reputation("")
        self.assertEqual(result["reputation_label"], "UNKNOWN")

    def test_extract_domain(self):
        self.assertEqual(extract_domain("https://www.example.com/path"), "www.example.com")
        self.assertEqual(extract_domain("http://192.168.1.1:8080/test"), "192.168.1.1")

    def test_get_tld(self):
        self.assertEqual(get_tld("example.com"), ".com")
        self.assertEqual(get_tld("evil.xyz"), ".xyz")


class TestEnrichmentPipelineIntegration(unittest.TestCase):
    """Test enrichment integration into the analysis pipeline."""

    def setUp(self):
        self.orchestrator = CitadelDetectorOrchestrator()

    def _make_eml(self, from_addr, body, urls_in_body=""):
        eml = (
            f"From: {from_addr}\r\n"
            f"To: victim@corp.com\r\n"
            f"Subject: Test\r\n"
            f"\r\n"
            f"{body}\r\n"
            f"{urls_in_body}\r\n"
        )
        return eml.encode()

    def test_analysis_includes_enrichment(self):
        """Analysis result should contain enrichment data."""
        parsed = parse_eml(self._make_eml(
            "test@example.com",
            "Hello world"
        ))
        result = self.orchestrator.analyze(parsed, "test.eml")
        self.assertIsNotNone(result.enrichment)
        self.assertIn("sender_domain", result.enrichment)

    def test_enrichment_sender_domain_analysis(self):
        """Sender domain should be analyzed for reputation."""
        result = enrich_sender_domain("user@google.com")
        self.assertIsNotNone(result)
        self.assertEqual(result["domain"], "google.com")
        self.assertTrue(result["is_known_legitimate"])


class TestEnrichmentAPIIntegration(unittest.TestCase):
    """Test enrichment appears in API responses."""

    def setUp(self):
        self.client = TestClient(app)

    def test_sample_analysis_includes_enrichment(self):
        """Sample analysis endpoint should include enrichment data."""
        response = self.client.get("/api/sample/credential_phishing_link.eml")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("enrichment", data)
        self.assertIsNotNone(data["enrichment"])


class TestGeoIP(unittest.TestCase):
    """Test IP geolocation and ASN intelligence."""

    def test_known_malicious_ip(self):
        from backend.geoip import geolocate_ip
        geo = geolocate_ip("198.51.100.42")
        self.assertTrue(geo["valid"])
        self.assertEqual(geo["country"], "Seychelles")
        self.assertEqual(geo["risk_category"], "HIGH_RISK")
        self.assertGreater(geo["risk_score"], 50)

    def test_tor_exit_node(self):
        from backend.geoip import geolocate_ip
        geo = geolocate_ip("185.220.101.5")
        self.assertTrue(geo["is_tor"])
        self.assertEqual(geo["risk_category"], "ANONYMIZER_TOR")

    def test_private_rfc1918_ip(self):
        from backend.geoip import geolocate_ip
        geo = geolocate_ip("192.168.1.10")
        self.assertTrue(geo["is_private"])
        self.assertEqual(geo["risk_category"], "INTERNAL")


class TestThreatIntel(unittest.TestCase):
    """Test IOC matching and threat actor attribution."""

    def test_domain_ioc_match(self):
        from backend.threat_intel import query_threat_intel
        res = query_threat_intel(domains=["secure-portal.xyz"], ips=[], urls=[])
        self.assertTrue(res["matched"])
        self.assertEqual(res["highest_severity"], "CRITICAL")
        self.assertIn("TA505 (EvilProxy Campaign)", res["attribution"])

    def test_clean_indicators(self):
        from backend.threat_intel import query_threat_intel
        res = query_threat_intel(domains=["clean-example.com"], ips=["1.1.1.1"], urls=[])
        self.assertFalse(res["matched"])
        self.assertEqual(res["highest_severity"], "NONE")


if __name__ == "__main__":
    unittest.main()
