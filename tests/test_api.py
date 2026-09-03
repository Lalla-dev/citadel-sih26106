"""
Citadel Security Platform - API Test Suite
Validates FastAPI endpoints: /api/health, /api/samples, /api/sample/{name}, and /api/analyze.
"""
import unittest
from pathlib import Path
from fastapi.testclient import TestClient
from backend.main import app

class TestCitadelAPI(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.samples_dir = Path(__file__).parent.parent / "samples"

    def test_health_check(self):
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "operational")

    def test_list_samples(self):
        res = self.client.get("/api/samples")
        self.assertEqual(res.status_code, 200)
        samples = res.json()
        self.assertGreaterEqual(len(samples), 4)
        filenames = [s["filename"] for s in samples]
        self.assertIn("benign_project_update.eml", filenames)
        self.assertIn("bec_ceo_wire_fraud.eml", filenames)

    def test_analyze_sample_endpoint(self):
        res = self.client.get("/api/sample/bec_ceo_wire_fraud.eml")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["case_id"].startswith("CASE-2026-"))
        self.assertEqual(data["threat_archetype"], "CEO Fraud / Executive Spoofing")
        self.assertGreaterEqual(data["threat_score"], 70)
        self.assertGreaterEqual(data["confidence"], 0.75)
        self.assertIn("reasons", data)
        self.assertIn("recommended_actions", data)
        self.assertFalse(data["authentication"]["live_verified"])

    def test_upload_eml_endpoint(self):
        file_path = self.samples_dir / "credential_phishing_link.eml"
        with open(file_path, "rb") as f:
            file_content = f.read()

        response = self.client.post(
            "/api/analyze",
            files={"file": ("credential_phishing_link.eml", file_content, "message/rfc822")}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["filename"], "credential_phishing_link.eml")
        self.assertEqual(data["threat_archetype"], "Credential Phishing")
        self.assertGreaterEqual(len(data["urls"]), 1)
        self.assertEqual(data["urls"][0]["risk_category"], "MALICIOUS")

if __name__ == "__main__":
    unittest.main()
