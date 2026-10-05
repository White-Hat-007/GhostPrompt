"""
GhostPrompt ML Pipeline — REAL Training Orchestrator

Runs the full end-to-end pipeline with REAL datasets and REAL GPU training:
  1. Download real datasets from HuggingFace Hub
  2. Merge and normalize all datasets
  3. Train Model A: Binary DistilBERT classifier (Fast Gate)
  4. Train Model B: Multi-class RoBERTa classifier (Attack Categories)
  5. Train Model C: Sentence-Transformer embedding engine (Zero-day Detection)

All models are trained with real GPU acceleration and saved to models/trained/
"""

import os
import sys
import time

# Ensure the backend directory is on the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    start = time.time()

    print("=" * 80, flush=True)
    print("  GhostPrompt — REAL ML Training Pipeline", flush=True)
    print("  🔥 NO MOCKS | REAL DATASETS | REAL GPU TRAINING", flush=True)
    print("=" * 80, flush=True)
    print(flush=True)

    # ─── Step 1: Download Real Datasets ──────────────────────────────────
    print("[STEP 1/2] Downloading real datasets from HuggingFace...", flush=True)
    print("-" * 60, flush=True)

    from training.dataset_downloader import download_all_datasets
    data = download_all_datasets()

    if not data:
        print("❌ No data downloaded. Cannot proceed with training.", flush=True)
        sys.exit(1)

    print(f"\n✅ Dataset ready: {len(data)} samples", flush=True)
    print(flush=True)

    # ─── Step 2: Train All Models ────────────────────────────────────────
    print("[STEP 2/2] Training all three ML models...", flush=True)
    print("-" * 60, flush=True)

    from training.real_trainer import main as train_main
    train_main()

    total = time.time() - start
    print(f"\n🏁 Total pipeline time: {total:.1f}s ({total/60:.1f} min)", flush=True)


if __name__ == "__main__":
    main()
