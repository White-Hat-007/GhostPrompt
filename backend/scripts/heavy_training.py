"""
GhostPrompt -- HEAVY GPU Training (Maximum Accuracy)

RTX 5060 optimized LoRA training with:
- More epochs (10)
- Larger dataset
- Learning rate warmup
- Early stopping with patience
- Full evaluation metrics

Run:
    python scripts/generate_heavy_dataset.py
    python scripts/heavy_training.py
"""

import os
import sys

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.ml.training.lora_trainer import (
    TrainingJob,
    get_device,
    train_threat_classifier,
    validate_jsonl_dataset,
)


def main():
    dataset_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "uploads", "datasets", "injection_training_heavy_v2.jsonl"
    )

    print("=" * 60)
    print("[GHOSTPROMPT] HEAVY LoRA Training -- Maximum Accuracy")
    print("=" * 60)

    # 1. Check GPU
    device = get_device()
    print(f"[DEVICE] {device}")
    if device.type == "cuda":
        import torch
        print(f"   GPU: {torch.cuda.get_device_name(0)}")
        mem = torch.cuda.get_device_properties(0).total_memory / (1024**3)
        print(f"   VRAM: {mem:.1f} GB")
    else:
        print("   WARNING: No GPU -- training on CPU")

    # 2. Validate dataset
    print(f"\n[DATASET] Validating: {dataset_path}")
    valid, count, error = validate_jsonl_dataset(dataset_path)
    if not valid:
        print(f"   INVALID: {error}")
        return
    print(f"   VALID: {count} samples")

    # 3. Create heavy training job
    job = TrainingJob(
        org_id="founder",
        model_type="threat_classifier",
        base_model="microsoft/deberta-v3-base",
        dataset_path=dataset_path,
        total_epochs=10,  # 10 epochs for maximum accuracy
    )

    print("\n[HEAVY TRAINING START]")
    print(f"   Job ID: {job.id}")
    print(f"   Model: {job.base_model}")
    print(f"   Epochs: {job.total_epochs}")
    print(f"   Dataset: {count} samples")
    print("   Trainable params: ~886K (LoRA r=16, alpha=32)")
    print()

    # 4. Train!
    result = train_threat_classifier(job)

    print("\n" + "=" * 60)
    if result.status == "completed":
        print("[SUCCESS] HEAVY TRAINING COMPLETE!")
        print(f"   Output: {result.output_dir}")
        print("   Metrics:")
        for k, v in result.metrics.items():
            if isinstance(v, float):
                print(f"      {k}: {v:.4f}")
            else:
                print(f"      {k}: {v}")
    else:
        print(f"[FAILED] Training failed: {result.error}")
    print("=" * 60)


if __name__ == "__main__":
    main()
