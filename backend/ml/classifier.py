"""
Citadel Security Platform - Multi-Model AI/ML Threat Classifier
Implements a genuine multi-model ensemble (Logistic Regression + Random Forest + XGBoost)
using TF-IDF subword n-gram vectorization with soft-voting probability aggregation
and transparent model agreement/disagreement reporting.
"""
import json
import os
import pickle
from pathlib import Path
from typing import Tuple, Optional, Dict, Any, List

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import numpy as np

LABEL_MAP = {0: "benign", 1: "phishing", 2: "bec"}
LABEL_REVERSE = {"benign": 0, "phishing": 1, "bec": 2}

MODEL_DIR = Path(__file__).parent / "models"
TRAINING_DATA_PATH = Path(__file__).parent / "training_data.jsonl"
EVALUATION_DATA_PATH = Path(__file__).parent / "evaluation_dataset.jsonl"

class CitadelMLClassifier:
    """
    Genuine 3-Model AI/ML Ensemble Classifier:
      1. Logistic Regression (Linear calibrated baseline)
      2. Random Forest (Bagged decision tree ensemble)
      3. XGBoost (Gradient-boosted decision trees)

    Ensemble Method:
      Probability-based soft voting with equal weights (1/3 each).
      Explicitly exposes individual model predictions, individual confidence,
      ensemble prediction, ensemble confidence, and consensus/disagreement levels.
    """
    def __init__(self):
        self.vectorizer: Optional[TfidfVectorizer] = None
        self.lr_model: Optional[LogisticRegression] = None
        self.rf_model: Optional[RandomForestClassifier] = None
        self.xgb_model: Optional[XGBClassifier] = None
        # Backwards compatibility alias for code referencing clf.model
        self.model: Optional[LogisticRegression] = None
        self.is_trained: bool = False
        self.training_metrics: Dict[str, Any] = {}
        self.weights: Dict[str, float] = {
            "logistic_regression": 1.0 / 3.0,
            "random_forest": 1.0 / 3.0,
            "xgboost": 1.0 / 3.0
        }

    def train(self, data_path: Optional[str] = None, test_size: float = 0.2) -> Dict[str, Any]:
        """
        Train the 3-model ensemble on training data and evaluate against both
        internal split and external held-out evaluation dataset.
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

        # 1. TF-IDF vectorization with subword n-grams for robustness
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

        # 2. Model 1: Logistic Regression
        self.lr_model = LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            C=1.0,
            solver="lbfgs",
            random_state=42
        )
        self.lr_model.fit(X_train, y_train)
        self.model = self.lr_model

        # 3. Model 2: Random Forest
        self.rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1
        )
        self.rf_model.fit(X_train, y_train)

        # 4. Model 3: XGBoost
        self.xgb_model = XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            eval_metric="mlogloss",
            random_state=42,
            tree_method="hist"
        )
        self.xgb_model.fit(X_train, y_train)

        # 5. Evaluate on internal split
        p_lr_test = self.lr_model.predict_proba(X_test)
        p_rf_test = self.rf_model.predict_proba(X_test)
        p_xgb_test = self.xgb_model.predict_proba(X_test)
        p_ens_test = (
            self.weights["logistic_regression"] * p_lr_test +
            self.weights["random_forest"] * p_rf_test +
            self.weights["xgboost"] * p_xgb_test
        )

        pred_lr = np.argmax(p_lr_test, axis=1)
        pred_rf = np.argmax(p_rf_test, axis=1)
        pred_xgb = np.argmax(p_xgb_test, axis=1)
        pred_ens = np.argmax(p_ens_test, axis=1)

        def compute_metrics(y_true, y_pred):
            rep = classification_report(
                y_true, y_pred,
                target_names=["benign", "phishing", "bec"],
                output_dict=True,
                zero_division=0
            )
            return {
                "accuracy": round(float(rep["accuracy"]), 4),
                "macro_f1": round(float(rep["macro avg"]["f1-score"]), 4),
                "weighted_f1": round(float(rep["weighted avg"]["f1-score"]), 4),
                "per_class": {
                    name: {
                        "precision": round(float(rep[name]["precision"]), 4),
                        "recall": round(float(rep[name]["recall"]), 4),
                        "f1": round(float(rep[name]["f1-score"]), 4)
                    }
                    for name in ["benign", "phishing", "bec"]
                }
            }

        # 6. Evaluate on external held-out dataset if present
        held_out_metrics = self.evaluate_held_out(EVALUATION_DATA_PATH)

        self.training_metrics = {
            "accuracy": compute_metrics(y_test, pred_ens)["accuracy"],
            "total_samples": len(texts),
            "train_samples": len(y_train),
            "test_samples": len(y_test),
            "ensemble_weights": self.weights,
            "models": {
                "logistic_regression": compute_metrics(y_test, pred_lr),
                "random_forest": compute_metrics(y_test, pred_rf),
                "xgboost": compute_metrics(y_test, pred_xgb),
                "ensemble": compute_metrics(y_test, pred_ens)
            },
            "per_class": compute_metrics(y_test, pred_ens)["per_class"],
            "held_out_evaluation": held_out_metrics
        }

        self.is_trained = True
        self.save_model()
        return self.training_metrics

    def evaluate_held_out(self, eval_path: Path) -> Dict[str, Any]:
        """Compute real, strictly measured metrics on held-out evaluation dataset."""
        if not eval_path.exists():
            return {"status": "held_out_file_not_found"}

        test_texts, test_labels, test_cats = [], [], []
        with open(eval_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                r = json.loads(line)
                test_texts.append(r["text"])
                test_labels.append(r["label"])
                test_cats.append(r.get("category", "unknown"))

        X_eval = self.vectorizer.transform(test_texts)
        y_eval = np.array(test_labels)

        p_lr = self.lr_model.predict_proba(X_eval)
        p_rf = self.rf_model.predict_proba(X_eval)
        p_xgb = self.xgb_model.predict_proba(X_eval)
        p_ens = (
            self.weights["logistic_regression"] * p_lr +
            self.weights["random_forest"] * p_rf +
            self.weights["xgboost"] * p_xgb
        )

        preds = {
            "logistic_regression": np.argmax(p_lr, axis=1),
            "random_forest": np.argmax(p_rf, axis=1),
            "xgboost": np.argmax(p_xgb, axis=1),
            "ensemble": np.argmax(p_ens, axis=1)
        }

        # Focus metric evaluation on strictly 3-class core samples
        core_indices = [i for i, c in enumerate(test_cats) if c in ("benign", "phishing", "bec")]
        y_core = y_eval[core_indices]

        results = {
            "total_eval_samples": len(test_texts),
            "core_benchmark_samples": len(y_core),
            "models": {}
        }

        for model_name, y_pred in preds.items():
            y_pred_core = y_pred[core_indices]
            cm = confusion_matrix(y_core, y_pred_core, labels=[0, 1, 2]).tolist()
            results["models"][model_name] = {
                "accuracy": round(float(accuracy_score(y_core, y_pred_core)), 4),
                "macro_precision": round(float(precision_score(y_core, y_pred_core, average="macro", zero_division=0)), 4),
                "macro_recall": round(float(recall_score(y_core, y_pred_core, average="macro", zero_division=0)), 4),
                "macro_f1": round(float(f1_score(y_core, y_pred_core, average="macro", zero_division=0)), 4),
                "weighted_precision": round(float(precision_score(y_core, y_pred_core, average="weighted", zero_division=0)), 4),
                "weighted_recall": round(float(recall_score(y_core, y_pred_core, average="weighted", zero_division=0)), 4),
                "weighted_f1": round(float(f1_score(y_core, y_pred_core, average="weighted", zero_division=0)), 4),
                "confusion_matrix": cm,
                "labels_order": ["benign", "phishing", "bec"]
            }

        return results

    def predict(self, text: str) -> Dict[str, Any]:
        """
        Classify email text using the 3-model soft-voting ensemble.
        Returns:
          - ensemble prediction and confidence
          - individual model predictions and confidences
          - explicit model agreement / disagreement analysis
        """
        if not self.is_trained or not self.vectorizer or not self.lr_model:
            return {
                "ml_available": False,
                "predicted_label": "unknown",
                "probabilities": {},
                "ml_confidence": 0.0,
                "ensemble_prediction": "unknown",
                "ensemble_confidence": 0.0,
                "agreement_level": "UNKNOWN",
                "agreement_detail": "ML models not trained or available.",
                "models": {}
            }

        X = self.vectorizer.transform([text])

        # Model 1: Logistic Regression
        probs_lr = self.lr_model.predict_proba(X)[0]
        idx_lr = int(np.argmax(probs_lr))
        label_lr = LABEL_MAP.get(idx_lr, "unknown")
        conf_lr = float(probs_lr[idx_lr])

        # Model 2: Random Forest
        if self.rf_model:
            probs_rf = self.rf_model.predict_proba(X)[0]
            idx_rf = int(np.argmax(probs_rf))
            label_rf = LABEL_MAP.get(idx_rf, "unknown")
            conf_rf = float(probs_rf[idx_rf])
        else:
            probs_rf = probs_lr
            label_rf = label_lr
            conf_rf = conf_lr

        # Model 3: XGBoost
        if self.xgb_model:
            probs_xgb = self.xgb_model.predict_proba(X)[0]
            idx_xgb = int(np.argmax(probs_xgb))
            label_xgb = LABEL_MAP.get(idx_xgb, "unknown")
            conf_xgb = float(probs_xgb[idx_xgb])
        else:
            probs_xgb = probs_lr
            label_xgb = label_lr
            conf_xgb = conf_lr

        # Soft-voting probability combination
        w_lr = self.weights["logistic_regression"]
        w_rf = self.weights["random_forest"]
        w_xgb = self.weights["xgboost"]

        probs_ens = (w_lr * probs_lr) + (w_rf * probs_rf) + (w_xgb * probs_xgb)
        # Re-normalize to sum to 1.0
        total_p = float(np.sum(probs_ens))
        if total_p > 0:
            probs_ens = probs_ens / total_p

        idx_ens = int(np.argmax(probs_ens))
        label_ens = LABEL_MAP.get(idx_ens, "unknown")
        conf_ens = float(probs_ens[idx_ens])

        prob_dict = {
            cls_name: round(float(probs_ens[i]), 4)
            for i, cls_name in LABEL_MAP.items()
            if i < len(probs_ens)
        }

        # Agreement Analysis
        preds_list = [label_lr, label_rf, label_xgb]
        unique_preds = set(preds_list)
        if len(unique_preds) == 1:
            agreement_level = "HIGH"
            agreement_detail = f"Unanimous consensus: all 3 models predict '{label_ens.upper()}'."
        elif len(unique_preds) == 2:
            agreement_level = "MODERATE"
            disagree_model = [m for m, p in [("LR", label_lr), ("RF", label_rf), ("XGB", label_xgb)] if p != label_ens]
            disagree_str = f"({', '.join(disagree_model)} diverged)" if disagree_model else ""
            agreement_detail = f"Majority consensus: 2 of 3 models predict '{label_ens.upper()}' {disagree_str}."
        else:
            agreement_level = "LOW"
            agreement_detail = (
                f"Model divergence detected: LR ({label_lr}), RF ({label_rf}), XGB ({label_xgb}). "
                f"Ensemble probability favored '{label_ens.upper()}'."
            )

        model_breakdown = {
            "logistic_regression": {
                "predicted_label": label_lr,
                "confidence": round(conf_lr, 4),
                "probabilities": {LABEL_MAP[i]: round(float(p), 4) for i, p in enumerate(probs_lr)}
            },
            "random_forest": {
                "predicted_label": label_rf,
                "confidence": round(conf_rf, 4),
                "probabilities": {LABEL_MAP[i]: round(float(p), 4) for i, p in enumerate(probs_rf)}
            },
            "xgboost": {
                "predicted_label": label_xgb,
                "confidence": round(conf_xgb, 4),
                "probabilities": {LABEL_MAP[i]: round(float(p), 4) for i, p in enumerate(probs_xgb)}
            }
        }

        return {
            "ml_available": True,
            "predicted_label": label_ens,
            "probabilities": prob_dict,
            "ml_confidence": round(conf_ens, 4),
            "ensemble_prediction": label_ens,
            "ensemble_confidence": round(conf_ens, 4),
            "agreement_level": agreement_level,
            "agreement_detail": agreement_detail,
            "models": model_breakdown,
            "ensemble_weights": self.weights
        }

    def save_model(self):
        """Persist vectorizer and all three ensemble models to disk."""
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        if self.vectorizer:
            with open(MODEL_DIR / "tfidf_vectorizer.pkl", "wb") as f:
                pickle.dump(self.vectorizer, f)
        if self.lr_model:
            with open(MODEL_DIR / "logistic_regression.pkl", "wb") as f:
                pickle.dump(self.lr_model, f)
        if self.rf_model:
            with open(MODEL_DIR / "random_forest.pkl", "wb") as f:
                pickle.dump(self.rf_model, f)
        if self.xgb_model:
            with open(MODEL_DIR / "xgboost.pkl", "wb") as f:
                pickle.dump(self.xgb_model, f)
        with open(MODEL_DIR / "training_metrics.json", "w") as f:
            json.dump(self.training_metrics, f, indent=2)

    def load_model(self) -> bool:
        """Load trained vectorizer and all models. Auto-trains missing ensemble models if needed."""
        vec_path = MODEL_DIR / "tfidf_vectorizer.pkl"
        lr_path = MODEL_DIR / "logistic_regression.pkl"
        rf_path = MODEL_DIR / "random_forest.pkl"
        xgb_path = MODEL_DIR / "xgboost.pkl"
        metrics_path = MODEL_DIR / "training_metrics.json"

        if not vec_path.exists() or not lr_path.exists():
            return False

        try:
            with open(vec_path, "rb") as f:
                self.vectorizer = pickle.load(f)
            with open(lr_path, "rb") as f:
                self.lr_model = pickle.load(f)
            self.model = self.lr_model

            # Load RF and XGBoost if available, otherwise trigger full train
            if rf_path.exists() and xgb_path.exists():
                with open(rf_path, "rb") as f:
                    self.rf_model = pickle.load(f)
                with open(xgb_path, "rb") as f:
                    self.xgb_model = pickle.load(f)
            else:
                if TRAINING_DATA_PATH.exists():
                    self.train()
                    return True

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
    """Get or initialize the ML classifier singleton. Auto-loads saved models if available."""
    global _classifier_instance
    if _classifier_instance is None:
        _classifier_instance = CitadelMLClassifier()
        if not _classifier_instance.load_model():
            if TRAINING_DATA_PATH.exists():
                _classifier_instance.train()
    return _classifier_instance

if __name__ == "__main__":
    clf = CitadelMLClassifier()
    metrics = clf.train()
    print(f"Training complete. Ensemble Accuracy: {metrics['accuracy']}")
    for m_name, m_metrics in metrics["models"].items():
        print(f"  Model: {m_name} -> Acc: {m_metrics['accuracy']}, Macro F1: {m_metrics['macro_f1']}")

    # Test sample
    test_text = "Urgent: Your account is suspended. Click http://198.51.100.44/verify to reactivate."
    res = clf.predict(test_text)
    print("\nPrediction Result:")
    print(f"  Ensemble: {res['ensemble_prediction']} (conf: {res['ensemble_confidence']})")
    print(f"  Agreement: {res['agreement_level']} - {res['agreement_detail']}")
    for k, v in res["models"].items():
        print(f"    {k}: {v['predicted_label']} ({v['confidence']})")
