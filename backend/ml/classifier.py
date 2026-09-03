"""
Citadel Security Platform - TF-IDF + Logistic Regression ML Classifier
Trains and serves a lightweight statistical phishing/BEC text classifier.
Complements (does NOT replace) the Phase 1 heuristic detection engine.
"""
import json
import os
import pickle
from pathlib import Path
from typing import Tuple, Optional, Dict, Any

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import numpy as np

LABEL_MAP = {0: "benign", 1: "phishing", 2: "bec"}
LABEL_REVERSE = {"benign": 0, "phishing": 1, "bec": 2}

MODEL_DIR = Path(__file__).parent / "models"
TRAINING_DATA_PATH = Path(__file__).parent / "training_data.jsonl"

class CitadelMLClassifier:
    """
    TF-IDF + Logistic Regression classifier for email text classification.
    Provides phishing probability, BEC probability, and predicted class.
    """
    def __init__(self):
        self.vectorizer: Optional[TfidfVectorizer] = None
        self.model: Optional[LogisticRegression] = None
        self.is_trained: bool = False
        self.training_metrics: Dict[str, Any] = {}

    def train(self, data_path: Optional[str] = None, test_size: float = 0.2) -> Dict[str, Any]:
        """
        Train the TF-IDF + LR classifier on the provided JSONL training data.
        Returns training metrics including accuracy and per-class F1 scores.
        """
        data_file = Path(data_path) if data_path else TRAINING_DATA_PATH
        if not data_file.exists():
            raise FileNotFoundError(f"Training data not found: {data_file}")

        texts = []
        labels = []
        with open(data_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                texts.append(record["text"])
                labels.append(record["label"])

        # TF-IDF vectorization with subword n-grams for robustness
        self.vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 2),
            min_df=2,
            max_df=0.95,
            strip_accents="unicode",
            lowercase=True,
            sublinear_tf=True
        )

        X = self.vectorizer.fit_transform(texts)
        y = np.array(labels)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )

        # Logistic Regression with class weight balancing
        self.model = LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            C=1.0,
            solver="lbfgs",
            random_state=42
        )
        self.model.fit(X_train, y_train)

        # Evaluate
        y_pred = self.model.predict(X_test)
        report = classification_report(
            y_test, y_pred,
            target_names=["benign", "phishing", "bec"],
            output_dict=True
        )

        accuracy = report["accuracy"]
        self.training_metrics = {
            "accuracy": round(accuracy, 4),
            "total_samples": len(texts),
            "train_samples": len(y_train),
            "test_samples": len(y_test),
            "per_class": {
                name: {
                    "precision": round(report[name]["precision"], 4),
                    "recall": round(report[name]["recall"], 4),
                    "f1": round(report[name]["f1-score"], 4),
                }
                for name in ["benign", "phishing", "bec"]
            }
        }

        self.is_trained = True
        self.save_model()
        return self.training_metrics

    def predict(self, text: str) -> Dict[str, Any]:
        """
        Classify a single email text.
        Returns predicted label, class probabilities, and ML confidence.
        """
        if not self.is_trained:
            return {
                "ml_available": False,
                "predicted_label": "unknown",
                "probabilities": {},
                "ml_confidence": 0.0
            }

        X = self.vectorizer.transform([text])
        probs = self.model.predict_proba(X)[0]
        predicted_idx = int(np.argmax(probs))

        prob_dict = {}
        for idx, cls_name in LABEL_MAP.items():
            if idx < len(probs):
                prob_dict[cls_name] = round(float(probs[idx]), 4)

        return {
            "ml_available": True,
            "predicted_label": LABEL_MAP.get(predicted_idx, "unknown"),
            "probabilities": prob_dict,
            "ml_confidence": round(float(probs[predicted_idx]), 4)
        }

    def save_model(self):
        """Persist trained model and vectorizer to disk."""
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        with open(MODEL_DIR / "tfidf_vectorizer.pkl", "wb") as f:
            pickle.dump(self.vectorizer, f)
        with open(MODEL_DIR / "logistic_regression.pkl", "wb") as f:
            pickle.dump(self.model, f)
        with open(MODEL_DIR / "training_metrics.json", "w") as f:
            json.dump(self.training_metrics, f, indent=2)

    def load_model(self) -> bool:
        """Load a previously trained model from disk. Returns True if successful."""
        vec_path = MODEL_DIR / "tfidf_vectorizer.pkl"
        model_path = MODEL_DIR / "logistic_regression.pkl"
        metrics_path = MODEL_DIR / "training_metrics.json"

        if not vec_path.exists() or not model_path.exists():
            return False

        try:
            with open(vec_path, "rb") as f:
                self.vectorizer = pickle.load(f)
            with open(model_path, "rb") as f:
                self.model = pickle.load(f)
            if metrics_path.exists():
                with open(metrics_path, "r") as f:
                    self.training_metrics = json.load(f)
            self.is_trained = True
            return True
        except Exception:
            self.is_trained = False
            return False

# Module-level singleton for the ML classifier
_classifier_instance: Optional[CitadelMLClassifier] = None

def get_ml_classifier() -> CitadelMLClassifier:
    """Get or initialize the ML classifier singleton. Auto-loads saved model if available."""
    global _classifier_instance
    if _classifier_instance is None:
        _classifier_instance = CitadelMLClassifier()
        if not _classifier_instance.load_model():
            # Auto-train if training data exists but no saved model
            if TRAINING_DATA_PATH.exists():
                _classifier_instance.train()
    return _classifier_instance

if __name__ == "__main__":
    clf = CitadelMLClassifier()
    metrics = clf.train()
    print(f"Training complete. Accuracy: {metrics['accuracy']}")
    for cls_name, cls_metrics in metrics["per_class"].items():
        print(f"  {cls_name}: P={cls_metrics['precision']} R={cls_metrics['recall']} F1={cls_metrics['f1']}")

    # Quick test
    test_phish = "Your account has been suspended. Click here to verify your credentials immediately."
    test_bec = "I need you to wire $50,000 to the following account. This is strictly confidential."
    test_benign = "Hi team, the sprint planning meeting is tomorrow at 10 AM."

    for text, expected in [(test_phish, "phishing"), (test_bec, "bec"), (test_benign, "benign")]:
        result = clf.predict(text)
        print(f"\n  Input: {text[:60]}...")
        print(f"  Predicted: {result['predicted_label']} (conf: {result['ml_confidence']})")
        print(f"  Probabilities: {result['probabilities']}")
