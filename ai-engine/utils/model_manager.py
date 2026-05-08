"""
Model Manager
Handles training, persistence, loading and metadata for the
ML threat classification pipeline.
Uses a VotingClassifier ensemble for maximum accuracy.
"""

import os
import json
import time
import pickle
import numpy as np
from datetime import datetime
from pathlib import Path

from sklearn.ensemble import (
    RandomForestClassifier,
    GradientBoostingClassifier,
    VotingClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    f1_score,
)

from utils.logger import get_logger

logger = get_logger("model_manager")

MODEL_DIR = Path(__file__).parent.parent / "models"
MODEL_DIR.mkdir(exist_ok=True)

MODEL_PATH    = MODEL_DIR / "threat_model.pkl"
METADATA_PATH = MODEL_DIR / "model_metadata.json"
ENCODER_PATH  = MODEL_DIR / "label_encoder.pkl"


class ModelManager:
    def __init__(self):
        self.pipeline = None
        self.label_encoder = None
        self.metadata = {}
        self._load_if_exists()

    # ─── Build Pipeline ────────────────────────────────────────────────────────
    def _build_pipeline(self):
        """
        Ensemble VotingClassifier:
        - RandomForest: handles non-linear boundaries, feature importance
        - GradientBoosting: sequential error correction
        - LogisticRegression: fast linear baseline with calibrated probabilities
        Combined with soft voting for probability averaging.
        """
        rf = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=4,
            min_samples_leaf=2,
            max_features="sqrt",
            class_weight="balanced",
            n_jobs=-1,
            random_state=42,
        )
        gb = GradientBoostingClassifier(
            n_estimators=150,
            learning_rate=0.08,
            max_depth=6,
            subsample=0.85,
            min_samples_split=4,
            random_state=42,
        )
        lr = LogisticRegression(
            C=1.5,
            max_iter=2000,
            class_weight="balanced",
            solver="lbfgs",
            random_state=42,
        )

        ensemble = VotingClassifier(
            estimators=[("rf", rf), ("gb", gb), ("lr", lr)],
            voting="soft",
            weights=[3, 2, 1],  # RF gets highest weight
        )

        pipeline = Pipeline([
            ("scaler", StandardScaler()),
            ("classifier", ensemble),
        ])

        return pipeline

    # ─── Train ────────────────────────────────────────────────────────────────
    def train(self, n_samples=15000, force=False):
        """Train the model pipeline on synthetic data."""
        # Lazy import to keep startup fast
        from data.data_generator import generate_dataset
        from utils.feature_engineer import FeatureEngineer

        logger.info(f"Starting model training | samples={n_samples}")
        start = time.time()

        fe = FeatureEngineer()
        samples = generate_dataset(n_samples=n_samples)

        # Build feature matrix + labels
        X = fe.transform_batch(samples)
        raw_labels = [s["severity"] for s in samples]

        self.label_encoder = LabelEncoder()
        y = self.label_encoder.fit_transform(raw_labels)

        logger.info(f"Feature matrix: {X.shape} | Classes: {self.label_encoder.classes_}")

        # Train/test split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.15, random_state=42, stratify=y
        )

        # Build and fit pipeline
        self.pipeline = self._build_pipeline()
        logger.info("Training ensemble model (RandomForest + GradientBoosting + LogisticRegression)...")
        self.pipeline.fit(X_train, y_train)

        # Evaluate
        y_pred = self.pipeline.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred, average="weighted")

        # Cross-validation score
        cv_scores = cross_val_score(self.pipeline, X_train, y_train, cv=3, scoring="accuracy", n_jobs=-1)

        elapsed = time.time() - start
        logger.info(f"Training complete in {elapsed:.1f}s")
        logger.info(f"Test accuracy: {accuracy:.4f} | F1: {f1:.4f} | CV: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

        # Feature importances (from RF)
        try:
            rf_clf = self.pipeline.named_steps["classifier"].estimators_[0]
            importances = rf_clf.feature_importances_.tolist()
        except Exception:
            importances = []

        # Save metadata
        report = classification_report(
            y_test, y_pred,
            target_names=self.label_encoder.classes_,
            output_dict=True
        )

        self.metadata = {
            "model_name": "EnsembleVotingClassifier",
            "version": "1.0.0",
            "trained_on": datetime.utcnow().isoformat(),
            "n_samples": n_samples,
            "n_features": X.shape[1],
            "classes": self.label_encoder.classes_.tolist(),
            "accuracy": round(accuracy, 6),
            "f1_weighted": round(f1, 6),
            "cv_mean": round(float(cv_scores.mean()), 6),
            "cv_std": round(float(cv_scores.std()), 6),
            "feature_importances": importances,
            "classification_report": report,
            "training_time_seconds": round(elapsed, 2),
        }

        self._save()

        metrics = {
            "accuracy": accuracy,
            "f1_weighted": f1,
            "cv_mean": float(cv_scores.mean()),
            "cv_std": float(cv_scores.std()),
            "training_time": elapsed,
            "n_samples": n_samples,
        }
        return metrics

    # ─── Predict ──────────────────────────────────────────────────────────────
    def predict(self, feature_vector):
        """
        Given a (1, n_features) numpy array, return:
        { severity, label_index, probabilities, confidence }
        """
        if self.pipeline is None or self.label_encoder is None:
            raise RuntimeError("Model not trained. Call train() first.")

        proba = self.pipeline.predict_proba(feature_vector)[0]
        label_idx = int(np.argmax(proba))
        severity = self.label_encoder.inverse_transform([label_idx])[0]
        confidence = float(proba[label_idx])

        # Build full probability map
        prob_map = {
            cls: round(float(p), 4)
            for cls, p in zip(self.label_encoder.classes_, proba)
        }

        return {
            "severity": severity,
            "label_index": label_idx,
            "confidence": round(confidence, 4),
            "probabilities": prob_map,
        }

    # ─── Save / Load ──────────────────────────────────────────────────────────
    def _save(self):
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(self.pipeline, f, protocol=pickle.HIGHEST_PROTOCOL)
        with open(ENCODER_PATH, "wb") as f:
            pickle.dump(self.label_encoder, f, protocol=pickle.HIGHEST_PROTOCOL)
        with open(METADATA_PATH, "w") as f:
            json.dump(self.metadata, f, indent=2)
        logger.info(f"Model saved to {MODEL_DIR}")

    def _load_if_exists(self):
        if MODEL_PATH.exists() and ENCODER_PATH.exists() and METADATA_PATH.exists():
            try:
                with open(MODEL_PATH, "rb") as f:
                    self.pipeline = pickle.load(f)
                with open(ENCODER_PATH, "rb") as f:
                    self.label_encoder = pickle.load(f)
                with open(METADATA_PATH, "r") as f:
                    self.metadata = json.load(f)
                logger.info(f"Loaded pre-trained model | accuracy={self.metadata.get('accuracy', 'N/A')}")
                return True
            except Exception as e:
                logger.warning(f"Failed to load saved model: {e}. Will retrain.")
                self.pipeline = None
                self.label_encoder = None
                self.metadata = {}
        return False

    def is_trained(self):
        return self.pipeline is not None and self.label_encoder is not None

    def get_status(self):
        return {
            "model_name": self.metadata.get("model_name", "Not trained"),
            "version":    self.metadata.get("version", "N/A"),
            "accuracy":   self.metadata.get("accuracy", 0.0),
            "trained_on": self.metadata.get("trained_on", "Never"),
            "n_features": self.metadata.get("n_features", 0),
            "classes":    self.metadata.get("classes", []),
        }

    def get_detailed_info(self):
        info = dict(self.metadata)
        if self.is_trained():
            info["pipeline_steps"] = [
                step[0] for step in self.pipeline.steps
            ]
        return info
