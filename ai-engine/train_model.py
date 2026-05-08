"""
Standalone Model Training Script
Run this to pre-train and save the model before starting the server.

Usage:
  python train_model.py              # default 15,000 samples
  python train_model.py --samples 30000
"""

import sys
import argparse
import time

def main():
    parser = argparse.ArgumentParser(description="Train the AI threat detection model")
    parser.add_argument("--samples", type=int, default=15000,
                        help="Number of training samples (default: 15000)")
    args = parser.parse_args()

    print("\n" + "="*55)
    print("  AI Threat Detection Model — Training")
    print("="*55)

    from utils.model_manager import ModelManager

    manager = ModelManager()

    print(f"\n  Training on {args.samples:,} synthetic samples...")
    print("  Model: EnsembleVotingClassifier")
    print("         (RandomForest + GradientBoosting + LogisticRegression)")
    print()

    start = time.time()
    metrics = manager.train(n_samples=args.samples, force=True)
    elapsed = time.time() - start

    print("\n" + "="*55)
    print("  Training Results:")
    print(f"  Accuracy:       {metrics['accuracy']*100:.2f}%")
    print(f"  F1 (weighted):  {metrics['f1_weighted']*100:.2f}%")
    print(f"  CV Mean:        {metrics['cv_mean']*100:.2f}% ± {metrics['cv_std']*100:.2f}%")
    print(f"  Training time:  {metrics['training_time']:.1f}s")
    print(f"  Samples:        {metrics['n_samples']:,}")
    print()
    print("  Model saved to: models/threat_model.pkl")
    print("="*55 + "\n")

if __name__ == "__main__":
    main()
