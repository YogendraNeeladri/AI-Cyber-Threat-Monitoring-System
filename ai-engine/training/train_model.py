"""
Model trainer for the AI Cyber Threat Detection Engine.
Trains multiple classifiers, selects best performer, saves pipeline + metadata.

Models trained:
  1. Random Forest        — fast, interpretable, handles imbalance well
  2. XGBoost              — best accuracy for tabular data
  3. Gradient Boosting    — strong baseline
  4. Voting Ensemble      — combines all three (used in production)
"""

import os
import sys
import json
import time
import joblib
import numpy as np
import pandas as pd
from datetime import datetime

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score,
    roc_auc_score, f1_score
)
from sklearn.utils.class_weight import compute_class_weight
from imblearn.over_sampling import SMOTE
import xgboost as xgb

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from training.generate_dataset import (
    generate_dataset, FEATURE_COLUMNS, SEVERITY_MAP, SEVERITY_REVERSE, ACTION_MAP
)

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'models')
os.makedirs(MODELS_DIR, exist_ok=True)

def train_models(samples_per_action: int = 1000, verbose: bool = True):
    if verbose:
        print("=" * 60)
        print("  AI Cyber Threat Detection — Model Trainer")
        print("=" * 60)

    # ─── 1. Generate dataset ──────────────────────────────────────
    if verbose:
        print("\n[1/6] Generating training dataset...")
    df = generate_dataset(samples_per_action=samples_per_action)

    X = df[FEATURE_COLUMNS].values
    y = df['severity_code'].values

    # ─── 2. Split ─────────────────────────────────────────────────
    if verbose:
        print("\n[2/6] Splitting dataset (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    # ─── 3. SMOTE to handle class imbalance ───────────────────────
    if verbose:
        print("\n[3/6] Applying SMOTE for class balancing...")
    smote = SMOTE(random_state=42, k_neighbors=3)
    X_train_bal, y_train_bal = smote.fit_resample(X_train, y_train)

    if verbose:
        unique, counts = np.unique(y_train_bal, return_counts=True)
        for u, c in zip(unique, counts):
            print(f"  {SEVERITY_REVERSE[u]:<10}: {c} samples")

    # ─── 4. Compute class weights ─────────────────────────────────
    classes = np.unique(y_train_bal)
    weights = compute_class_weight('balanced', classes=classes, y=y_train_bal)
    class_weight_dict = dict(zip(classes, weights))

    # ─── 5. Define models ─────────────────────────────────────────
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_bal)
    X_test_scaled  = scaler.transform(X_test)

    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight='balanced',
        n_jobs=-1,
        random_state=42,
    )

    xgb_model = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        use_label_encoder=False,
        eval_metric='mlogloss',
        random_state=42,
        verbosity=0,
    )

    gb = GradientBoostingClassifier(
        n_estimators=150,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        random_state=42,
    )

    ensemble = VotingClassifier(
        estimators=[('rf', rf), ('xgb', xgb_model), ('gb', gb)],
        voting='soft',
        n_jobs=-1,
    )

    # ─── 6. Train + evaluate ──────────────────────────────────────
    if verbose:
        print("\n[4/6] Training classifiers...")

    model_results = {}
    trained_models = {}

    for name, model in [('RandomForest', rf), ('XGBoost', xgb_model),
                         ('GradientBoosting', gb), ('VotingEnsemble', ensemble)]:
        if verbose:
            print(f"\n  Training {name}...")
        t0 = time.time()
        model.fit(X_train_scaled, y_train_bal)
        duration = time.time() - t0

        y_pred  = model.predict(X_test_scaled)
        y_proba = model.predict_proba(X_test_scaled)

        acc  = accuracy_score(y_test, y_pred)
        f1   = f1_score(y_test, y_pred, average='weighted')
        try:
            auc = roc_auc_score(y_test, y_proba, multi_class='ovr', average='weighted')
        except Exception:
            auc = 0.0

        model_results[name] = {
            'accuracy': round(acc, 4),
            'f1_weighted': round(f1, 4),
            'auc_ovr': round(auc, 4),
            'train_seconds': round(duration, 2),
        }
        trained_models[name] = model

        if verbose:
            print(f"  Accuracy: {acc:.4f} | F1: {f1:.4f} | AUC: {auc:.4f} | Time: {duration:.1f}s")

    # ─── 7. Pick best model ───────────────────────────────────────
    best_name = max(model_results, key=lambda k: model_results[k]['f1_weighted'])
    best_model = trained_models[best_name]

    if verbose:
        print(f"\n[5/6] Best model: {best_name}")
        print("\nFull classification report:")
        y_pred_best = best_model.predict(X_test_scaled)
        target_names = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        print(classification_report(y_test, y_pred_best, target_names=target_names))

    # Cross-validation
    if verbose:
        print("[6/6] Running 5-fold cross-validation on best model...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(best_model, X_train_scaled, y_train_bal,
                                cv=cv, scoring='f1_weighted', n_jobs=-1)
    if verbose:
        print(f"  CV F1 scores: {cv_scores.round(4)}")
        print(f"  Mean CV F1:   {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # ─── 8. Save artifacts ────────────────────────────────────────
    pipeline = {
        'scaler': scaler,
        'model':  best_model,
        'model_name': best_name,
    }
    joblib.dump(pipeline, os.path.join(MODELS_DIR, 'threat_pipeline.pkl'))
    joblib.dump(scaler,   os.path.join(MODELS_DIR, 'scaler.pkl'))

    metadata = {
        'model_name':       best_name,
        'version':          '1.0.0',
        'trained_at':       datetime.utcnow().isoformat() + 'Z',
        'n_features':       len(FEATURE_COLUMNS),
        'feature_names':    FEATURE_COLUMNS,
        'action_map':       ACTION_MAP,
        'severity_map':     SEVERITY_MAP,
        'severity_reverse': SEVERITY_REVERSE,
        'performance':      model_results,
        'best_model_cv': {
            'mean_f1': round(float(cv_scores.mean()), 4),
            'std_f1':  round(float(cv_scores.std()), 4),
            'scores':  [round(float(s), 4) for s in cv_scores],
        },
        'classes': ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
        'training_samples': len(X_train_bal),
        'test_samples':     len(X_test),
    }

    with open(os.path.join(MODELS_DIR, 'metadata.json'), 'w') as f:
        json.dump(metadata, f, indent=2)

    if verbose:
        print(f"\nModel artifacts saved to: {MODELS_DIR}/")
        print(f"  threat_pipeline.pkl  ({os.path.getsize(os.path.join(MODELS_DIR,'threat_pipeline.pkl'))//1024} KB)")
        print(f"  metadata.json")
        print("\n" + "=" * 60)
        print("  Training complete!")
        print("=" * 60)

    return pipeline, metadata

if __name__ == '__main__':
    train_models(samples_per_action=1200, verbose=True)
