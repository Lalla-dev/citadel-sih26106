"""
Citadel Phase 2 Tests - ML Classification (TF-IDF + Logistic Regression)
Tests the ML classifier integration with the existing pipeline.
"""
import unittest
from backend.ml.classifier import CitadelMLClassifier, get_ml_classifier
from backend.parser import parse_eml
from backend.detector import CitadelDetectorOrchestrator
from fastapi.testclient import TestClient
from backend.main import app


class TestMLClassifier(unittest.TestCase):
    """Tests for the standalone ML classifier."""

    def setUp(self):
        self.clf = get_ml_classifier()

    def test_ml_model_is_trained(self):
        """Verify ML model auto-loads and reports trained."""
        self.assertTrue(self.clf.is_trained)

    def test_ml_predicts_phishing(self):
        """ML should classify obvious phishing text as phishing."""
        result = self.clf.predict(
            "URGENT: Your account has been compromised. Click here to verify your identity immediately."
        )
        self.assertTrue(result["ml_available"])
        self.assertEqual(result["predicted_label"], "phishing")
        self.assertGreater(result["ml_confidence"], 0.5)

    def test_ml_predicts_bec(self):
        """ML should classify BEC wire fraud text as BEC."""
        result = self.clf.predict(
            "I need you to wire $150,000 to the following account immediately. "
            "This is strictly confidential. Do not discuss with anyone."
        )
        self.assertTrue(result["ml_available"])
        self.assertEqual(result["predicted_label"], "bec")
        self.assertGreater(result["ml_confidence"], 0.5)

    def test_ml_predicts_benign(self):
        """ML should classify ordinary business text as benign."""
        result = self.clf.predict(
            "Hi team, the weekly sprint planning meeting is tomorrow at 10 AM in the main conference room."
        )
        self.assertTrue(result["ml_available"])
        self.assertEqual(result["predicted_label"], "benign")
        self.assertGreater(result["ml_confidence"], 0.4)

    def test_ml_returns_probability_dict(self):
        """Prediction result should contain probabilities for all three classes."""
        result = self.clf.predict("test text")
        self.assertIn("probabilities", result)
        probs = result["probabilities"]
        self.assertIn("benign", probs)
        self.assertIn("phishing", probs)
        self.assertIn("bec", probs)
        # Probabilities should sum to ~1.0
        total = sum(probs.values())
        self.assertAlmostEqual(total, 1.0, places=2)

    def test_ensemble_contains_three_models(self):
        """Ensemble classifier must incorporate Logistic Regression, Random Forest, and XGBoost."""
        self.assertIsNotNone(self.clf.lr_model, "Logistic Regression model should be initialized")
        self.assertIsNotNone(self.clf.rf_model, "Random Forest model should be initialized")
        self.assertIsNotNone(self.clf.xgb_model, "XGBoost model should be initialized")
        result = self.clf.predict("Your password will expire in 2 hours. Click to verify.")
        self.assertIn("models", result)
        self.assertIn("logistic_regression", result["models"])
        self.assertIn("random_forest", result["models"])
        self.assertIn("xgboost", result["models"])

    def test_ensemble_agreement_and_disagreement_exposed(self):
        """Predictions must expose agreement level (HIGH/MODERATE/LOW) and detail."""
        res_phish = self.clf.predict("URGENT: Your account has been compromised. Click here immediately.")
        self.assertIn("agreement_level", res_phish)
        self.assertIn(res_phish["agreement_level"], ["HIGH", "MODERATE", "LOW"])
        self.assertIn("agreement_detail", res_phish)

    def test_held_out_evaluation_metrics_computed(self):
        """Training metrics must include held_out_evaluation for all 4 models."""
        metrics = self.clf.training_metrics
        self.assertIn("held_out_evaluation", metrics)
        held_out = metrics["held_out_evaluation"]
        self.assertIn("models", held_out)
        self.assertIn("logistic_regression", held_out["models"])
        self.assertIn("random_forest", held_out["models"])
        self.assertIn("xgboost", held_out["models"])
        self.assertIn("ensemble", held_out["models"])
        ens_metrics = held_out["models"]["ensemble"]
        self.assertGreater(ens_metrics["accuracy"], 0.70)
        self.assertIn("confusion_matrix", ens_metrics)


class TestMLPipelineIntegration(unittest.TestCase):
    """Tests that ML classification integrates into the detection pipeline."""

    def setUp(self):
        self.orchestrator = CitadelDetectorOrchestrator()

    def _make_eml(self, subject, body):
        """Helper to create a minimal .eml bytes for testing."""
        eml = f"From: test@example.com\r\nTo: victim@corp.com\r\nSubject: {subject}\r\n\r\n{body}\r\n"
        return eml.encode()

    def test_pipeline_includes_ml_classification(self):
        """Analysis result should contain ml_classification field."""
        parsed = parse_eml(self._make_eml("Test", "Hello world"))
        result = self.orchestrator.analyze(parsed, "test.eml")
        self.assertTrue(hasattr(result, 'ml_classification'))
        self.assertTrue(result.ml_classification.ml_available)

    def test_pipeline_ml_boosts_phishing_score(self):
        """ML classification should boost threat score for phishing emails."""
        phishing_body = (
            "Your account has been suspended due to unauthorized activity. "
            "Click here immediately to verify your identity and restore access."
        )
        parsed = parse_eml(self._make_eml("URGENT: Account Suspended", phishing_body))
        result = self.orchestrator.analyze(parsed, "phish_test.eml")
        # Should have ML classification reason in reasons
        ml_reasons = [r for r in result.reasons if r.category == "ML Classification"]
        self.assertGreater(len(ml_reasons), 0, "ML classification should contribute a detection reason")

    def test_pipeline_benign_email_stays_low(self):
        """A clearly benign email should remain low-scoring with ML integration."""
        benign_body = "Hi team, the design review meeting has been moved to 3 PM tomorrow."
        parsed = parse_eml(self._make_eml("Meeting Update", benign_body))
        result = self.orchestrator.analyze(parsed, "benign_test.eml")
        self.assertLess(result.threat_score, 30)
        self.assertEqual(result.risk_level, "LOW")


class TestMLAPIEndpoints(unittest.TestCase):
    """Test ML-related API endpoints."""

    def setUp(self):
        self.client = TestClient(app)

    def test_ml_status_endpoint(self):
        """ML status API should return model availability and metrics."""
        response = self.client.get("/api/ml/status")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["ml_available"])
        self.assertEqual(data["model_type"], "TF-IDF + Logistic Regression")
        self.assertIn("training_metrics", data)

    def test_health_check_includes_ml(self):
        """Health check should report ML engine status."""
        response = self.client.get("/api/health")
        data = response.json()
        self.assertEqual(data["ml_engine"], "active")

    def test_analysis_response_includes_ml(self):
        """Sample analysis API should include ml_classification in response."""
        response = self.client.get("/api/sample/credential_phishing_link.eml")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("ml_classification", data)
        self.assertTrue(data["ml_classification"]["ml_available"])
        self.assertIn("predicted_label", data["ml_classification"])


if __name__ == "__main__":
    unittest.main()
