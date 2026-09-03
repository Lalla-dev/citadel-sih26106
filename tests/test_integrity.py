"""
Citadel Phase 9 Tests - Cryptographic Evidence Integrity & Blockchain Ledger
Tests SHA-256 raw evidence hashing, verdict digests, ledger linkage, tamper detection,
and verification API endpoints.
"""
import unittest
import hashlib
from backend.integrity import (
    EvidenceLedger,
    compute_sha256_bytes,
    compute_verdict_digest,
    compute_merkle_root,
    compute_block_hash,
    get_evidence_ledger
)
from backend.parser import parse_eml
from backend.detector import CitadelDetectorOrchestrator
from fastapi.testclient import TestClient
from backend.main import app


class TestCryptographicIntegrityEngine(unittest.TestCase):
    """Test cryptographic functions, ledger construction, and tamper detection."""

    def setUp(self):
        self.ledger = EvidenceLedger()
        self.sample_eml_1 = b"From: attacker@bad.com\r\nSubject: Wire Funds\r\n\r\nImmediate payment needed."
        self.sample_eml_2 = b"From: hr@corp.com\r\nSubject: Welcome\r\n\r\nWelcome to the company."

    def test_1_deterministic_evidence_sha256(self):
        """Known raw .eml bytes produce identical, deterministic SHA-256 digest."""
        hash1 = compute_sha256_bytes(self.sample_eml_1)
        hash2 = compute_sha256_bytes(self.sample_eml_1)
        expected = hashlib.sha256(self.sample_eml_1).hexdigest()
        self.assertEqual(hash1, expected)
        self.assertEqual(hash1, hash2)

    def test_2_different_evidence_produces_different_hash(self):
        """Distinct email evidence inputs produce distinct SHA-256 hashes."""
        hash1 = compute_sha256_bytes(self.sample_eml_1)
        hash2 = compute_sha256_bytes(self.sample_eml_2)
        self.assertNotEqual(hash1, hash2)

    def test_3_verdict_header_digest_deterministic(self):
        """Header + verdict canonical digest is completely deterministic."""
        headers = {"subject": "Test", "sender": "a@b.com", "recipient": "c@d.com"}
        verdict = {"threat_score": 85, "risk_level": "CRITICAL", "threat_archetype": "BEC"}
        d1 = compute_verdict_digest(headers, verdict)
        d2 = compute_verdict_digest(headers, verdict)
        self.assertEqual(d1, d2)
        self.assertEqual(len(d1), 64)

    def test_4_ledger_blocks_link_correctly(self):
        """Ledger blocks form a valid chain linked by previous_block_hash."""
        b1 = self.ledger.record_case_evidence(
            case_id="CASE-001",
            raw_eml_bytes=self.sample_eml_1,
            headers_dict={"subject": "S1"},
            verdict_dict={"threat_score": 80, "risk_level": "HIGH", "threat_archetype": "Phishing"}
        )
        b2 = self.ledger.record_case_evidence(
            case_id="CASE-002",
            raw_eml_bytes=self.sample_eml_2,
            headers_dict={"subject": "S2"},
            verdict_dict={"threat_score": 10, "risk_level": "LOW", "threat_archetype": "Clean"}
        )

        self.assertEqual(b1["block_index"], 1)
        self.assertEqual(b2["block_index"], 2)
        self.assertEqual(b1["previous_block_hash"], self.ledger.chain[0]["block_hash"])
        self.assertEqual(b2["previous_block_hash"], b1["block_hash"])

        valid, err = self.ledger.verify_ledger_integrity()
        self.assertTrue(valid)
        self.assertIsNone(err)

    def test_5_previous_block_hash_tampering_detected(self):
        """Tampering with previous_block_hash in chain is immediately detected."""
        self.ledger.record_case_evidence("CASE-T1", self.sample_eml_1, {}, {"threat_score": 50})
        self.ledger.record_case_evidence("CASE-T2", self.sample_eml_2, {}, {"threat_score": 20})

        # Corrupt chain linkage
        self.ledger.simulate_tamper_block(2, "0" * 64)

        valid, err = self.ledger.verify_ledger_integrity()
        self.assertFalse(valid)
        self.assertIn("Broken chain linkage", str(err))

    def test_6_evidence_tampering_detected(self):
        """Tampering with original raw .eml bytes causes verification failure."""
        self.ledger.record_case_evidence("CASE-EV1", self.sample_eml_1, {}, {"threat_score": 90})
        
        # Verify untouched
        res_clean = self.ledger.verify_case("CASE-EV1")
        self.assertEqual(res_clean["status"], "INTEGRITY: VERIFIED")
        self.assertTrue(res_clean["checks"]["evidence_hash_match"])

        # Tamper original evidence
        self.ledger.simulate_tamper_evidence("CASE-EV1", b"ALTERED_BODY_OF_EMAIL")
        res_tampered = self.ledger.verify_case("CASE-EV1")
        self.assertEqual(res_tampered["status"], "INTEGRITY: TAMPERED")
        self.assertFalse(res_tampered["checks"]["evidence_hash_match"])
        self.assertFalse(res_tampered["verified"])

    def test_7_verdict_tampering_detected(self):
        """Tampering with recorded threat verdict score is detected."""
        self.ledger.record_case_evidence("CASE-VD1", self.sample_eml_1, {"subject": "Test"}, {"threat_score": 95, "risk_level": "CRITICAL", "threat_archetype": "BEC"})
        
        # Tamper verdict (e.g. malicious actor lowers threat score to 0)
        self.ledger.simulate_tamper_verdict("CASE-VD1", 0)
        res_tampered = self.ledger.verify_case("CASE-VD1")
        self.assertEqual(res_tampered["status"], "INTEGRITY: TAMPERED")
        self.assertFalse(res_tampered["checks"]["verdict_hash_match"])

    def test_8_verification_succeeds_for_untouched_evidence(self):
        """Verification passes all checks for unmodified evidence."""
        self.ledger.record_case_evidence(
            "CASE-OK",
            self.sample_eml_1,
            {"subject": "Wire", "sender": "attacker@bad.com"},
            {"threat_score": 90, "risk_level": "CRITICAL", "threat_archetype": "BEC"}
        )
        res = self.ledger.verify_case("CASE-OK")
        self.assertEqual(res["status"], "INTEGRITY: VERIFIED")
        self.assertTrue(res["verified"])
        self.assertTrue(res["checks"]["evidence_hash_match"])
        self.assertTrue(res["checks"]["verdict_hash_match"])
        self.assertTrue(res["checks"]["ledger_linkage_valid"])
        self.assertTrue(res["checks"]["merkle_root_valid"])

    def test_9_verification_returns_tampered_after_modification(self):
        """Verification explicitly returns 'INTEGRITY: TAMPERED'."""
        self.ledger.record_case_evidence("CASE-MOD", self.sample_eml_1, {}, {"threat_score": 75})
        self.ledger.simulate_tamper_evidence("CASE-MOD", b"MODIFIED_EVIDENCE")
        res = self.ledger.verify_case("CASE-MOD")
        self.assertEqual(res["status"], "INTEGRITY: TAMPERED")
        self.assertIn("TAMPER DETECTED", res["summary"])

    def test_10_multiple_cases_do_not_corrupt_one_another(self):
        """Multiple cases sequentially added maintain independent integrity."""
        cases = [f"CASE-MULTI-{i}" for i in range(5)]
        for i, cid in enumerate(cases):
            raw = f"From: user{i}@test.com\r\nSubject: Msg {i}\r\n\r\nBody {i}".encode()
            self.ledger.record_case_evidence(cid, raw, {"subject": f"Msg {i}"}, {"threat_score": i * 20})

        # All 5 must independently verify
        for cid in cases:
            res = self.ledger.verify_case(cid)
            self.assertEqual(res["status"], "INTEGRITY: VERIFIED")
            self.assertTrue(res["verified"])


class TestIntegrityPipelineAndAPI(unittest.TestCase):
    """Test full pipeline integration and FastAPI verification endpoints."""

    def setUp(self):
        self.client = TestClient(app)
        self.orchestrator = CitadelDetectorOrchestrator()

    def test_pipeline_attaches_evidence_integrity(self):
        """End-to-end analysis produces populated EvidenceIntegrity object."""
        raw = b"From: ceo@exec.com\r\nSubject: Urgent\r\n\r\nImmediate transfer required."
        parsed = parse_eml(raw)
        result = self.orchestrator.analyze(parsed, filename="ceo.eml", raw_bytes=raw)

        self.assertIsNotNone(result.integrity)
        self.assertEqual(result.integrity.integrity_status, "INTEGRITY: VERIFIED")
        self.assertEqual(result.integrity.evidence_sha256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(len(result.integrity.verdict_sha256), 64)
        self.assertEqual(len(result.integrity.merkle_root), 64)
        self.assertGreaterEqual(result.integrity.block_index, 1)

    def test_verify_integrity_api_endpoint(self):
        """POST /api/case/{id}/verify-integrity returns VERIFIED for sample analysis."""
        # 1. Analyze sample
        sample_resp = self.client.get("/api/sample/credential_phishing_link.eml")
        self.assertEqual(sample_resp.status_code, 200)
        data = sample_resp.json()
        case_id = data["case_id"]

        # 2. Verify integrity
        verify_resp = self.client.post(f"/api/case/{case_id}/verify-integrity")
        self.assertEqual(verify_resp.status_code, 200)
        vdata = verify_resp.json()
        self.assertEqual(vdata["status"], "INTEGRITY: VERIFIED")
        self.assertTrue(vdata["verified"])
        self.assertTrue(vdata["checks"]["evidence_hash_match"])

    def test_simulate_tamper_and_detect_via_api(self):
        """Tampering simulated via API causes /verify-integrity to return TAMPERED."""
        # 1. Analyze
        sample_resp = self.client.get("/api/sample/bec_ceo_wire_fraud.eml")
        self.assertEqual(sample_resp.status_code, 200)
        case_id = sample_resp.json()["case_id"]

        # 2. Simulate tamper
        t_resp = self.client.post(f"/api/case/{case_id}/simulate-tamper?action=evidence")
        self.assertEqual(t_resp.status_code, 200)

        # 3. Verify integrity must now return TAMPERED
        v_resp = self.client.post(f"/api/case/{case_id}/verify-integrity")
        self.assertEqual(v_resp.status_code, 200)
        vdata = v_resp.json()
        self.assertEqual(vdata["status"], "INTEGRITY: TAMPERED")
        self.assertFalse(vdata["verified"])
        self.assertFalse(vdata["checks"]["evidence_hash_match"])


if __name__ == "__main__":
    unittest.main()
