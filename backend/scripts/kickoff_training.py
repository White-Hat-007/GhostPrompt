"""
GhostPrompt -- Real GPU Training Kickoff Script

Kicks off a LoRA fine-tuning job on the RTX 5060 using the injection_training_v1.jsonl dataset.
Run from the backend directory:
    python -m scripts.kickoff_training
"""

import sys
import os

# Force UTF-8 output on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# Add the backend directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.ml.training.lora_trainer import (
    TrainingJob, train_threat_classifier, validate_jsonl_dataset, get_device
)

def main():
    dataset_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "uploads", "datasets", "injection_training_v1.jsonl"
    )

    print("=" * 60)
    print("[GHOSTPROMPT] LoRA Training Kickoff")
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
        print("   WARNING: No GPU detected -- training will run on CPU (slower)")

    # 2. Validate dataset
    print(f"\n[DATASET] Validating: {dataset_path}")
    valid, count, error = validate_jsonl_dataset(dataset_path)
    if not valid:
        print(f"   INVALID: {error}")
        return
    print(f"   VALID: {count} samples")

    # 3. Create training job
    job = TrainingJob(
        org_id="founder",
        model_type="threat_classifier",
        base_model="microsoft/deberta-v3-base",
        dataset_path=dataset_path,
        total_epochs=3,  # 3 epochs for the initial run
    )

    print(f"\n[TRAINING START]")
    print(f"   Job ID: {job.id}")
    print(f"   Model: {job.base_model}")
    print(f"   Epochs: {job.total_epochs}")
    print(f"   Dataset: {count} samples")
    print()

    # 4. Train!
    result = train_threat_classifier(job)

    print("\n" + "=" * 60)
    if result.status == "completed":
        print("[SUCCESS] TRAINING COMPLETE!")
        print(f"   Output: {result.output_dir}")
        print(f"   Metrics: {result.metrics}")
    else:
        print(f"[FAILED] Training failed: {result.error}")
    print("=" * 60)


if __name__ == "__main__":
    main()
