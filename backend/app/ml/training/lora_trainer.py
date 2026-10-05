"""
GhostPrompt LoRA Training Pipeline — Real GPU Training on RTX 5060

Trains LoRA/PEFT adapters on DeBERTa-v3-base for per-tenant threat classification.
Also supports fine-tuning sentence-transformers for zero-day embedding detection.

Uses HuggingFace PEFT + Trainer with RTX 5060 CUDA acceleration.
"""

import os
import json
import uuid
import time
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

import torch
from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger("ml.training")
settings = get_settings()

TRAINING_DIR = Path(settings.TRAINING_OUTPUT_DIR)
TRAINING_DIR.mkdir(parents=True, exist_ok=True)

MODEL_CACHE = Path(settings.MODEL_CACHE_DIR)
MODEL_CACHE.mkdir(parents=True, exist_ok=True)


@dataclass
class TrainingJob:
    """Represents a training job."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    org_id: str = ""
    model_type: str = "threat_classifier"  # threat_classifier | zero_day_embedding
    base_model: str = "microsoft/deberta-v3-base"
    dataset_path: str = ""
    status: str = "pending"  # pending | running | completed | failed
    progress: float = 0.0
    current_epoch: int = 0
    total_epochs: int = 5
    metrics: dict = field(default_factory=dict)
    output_dir: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None


# ── In-memory job registry (production would use Redis/DB) ──
_active_jobs: dict[str, TrainingJob] = {}


def get_device() -> torch.device:
    """Get the best available device."""
    if torch.cuda.is_available():
        device = torch.device("cuda:0")
        gpu_name = torch.cuda.get_device_name(0)
        gpu_mem = torch.cuda.get_device_properties(0).total_memory / (1024**3)
        logger.info("gpu_detected", device=gpu_name, memory_gb=f"{gpu_mem:.1f}")
        return device
    logger.warning("no_gpu_detected_using_cpu")
    return torch.device("cpu")


def validate_jsonl_dataset(path: str) -> tuple[bool, int, str]:
    """Validate a JSONL dataset file. Returns (valid, count, error)."""
    try:
        count = 0
        with open(path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                
                # Check for either classification format or embedding format
                is_cls = "text" in record and "label" in record
                is_emb = "text_a" in record and "text_b" in record and "label" in record
                
                if not (is_cls or is_emb):
                    return False, 0, f"Line {i+1}: missing required fields ('text'+'label' or 'text_a'+'text_b'+'label')"
                count += 1
        if count < 10:
            return False, count, "Dataset must have at least 10 samples"
        return True, count, ""
    except Exception as e:
        return False, 0, str(e)


def train_threat_classifier(
    job: TrainingJob,
    progress_callback=None,
) -> TrainingJob:
    """
    Fine-tune a DeBERTa-v3-base model with LoRA for threat classification.
    
    Uses PEFT/LoRA for parameter-efficient training on the RTX 5060.
    """
    try:
        job.status = "running"
        job.started_at = datetime.now(timezone.utc).isoformat()
        _active_jobs[job.id] = job

        logger.info("training_started", job_id=job.id, model=job.base_model, org=job.org_id)

        # Lazy imports to avoid loading heavy libs at module level
        from transformers import (
            AutoTokenizer, AutoModelForSequenceClassification,
            TrainingArguments, Trainer, EarlyStoppingCallback,
        )
        from peft import LoraConfig, get_peft_model, TaskType
        from datasets import Dataset
        import numpy as np
        from sklearn.metrics import accuracy_score, precision_recall_fscore_support

        device = get_device()

        # ── Load dataset ──
        records = []
        label_set = set()
        with open(job.dataset_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                records.append(rec)
                label_set.add(rec["label"])

        labels = sorted(label_set)
        label2id = {l: i for i, l in enumerate(labels)}
        id2label = {i: l for l, i in label2id.items()}
        num_labels = len(labels)

        logger.info("dataset_loaded", samples=len(records), labels=num_labels, label_names=labels)

        # ── Split train/val (90/10) ──
        np.random.seed(42)
        indices = np.random.permutation(len(records))
        split = int(0.9 * len(records))
        train_records = [records[i] for i in indices[:split]]
        val_records = [records[i] for i in indices[split:]]

        # ── Tokenize ──
        tokenizer = AutoTokenizer.from_pretrained(job.base_model, cache_dir=str(MODEL_CACHE))

        def tokenize(batch):
            tokens = tokenizer(
                batch["text"],
                padding="max_length",
                truncation=True,
                max_length=256,
            )
            tokens["labels"] = [label2id[l] for l in batch["label"]]
            return tokens

        train_ds = Dataset.from_list(train_records).map(tokenize, batched=True, remove_columns=["text", "label"])
        val_ds = Dataset.from_list(val_records).map(tokenize, batched=True, remove_columns=["text", "label"])
        train_ds.set_format("torch")
        val_ds.set_format("torch")

        # ── Load base model ──
        model = AutoModelForSequenceClassification.from_pretrained(
            job.base_model,
            num_labels=num_labels,
            id2label=id2label,
            label2id=label2id,
            cache_dir=str(MODEL_CACHE),
        )

        # ── Apply LoRA ──
        lora_config = LoraConfig(
            task_type=TaskType.SEQ_CLS,
            r=16,                    # LoRA rank
            lora_alpha=32,           # LoRA alpha
            lora_dropout=0.1,
            target_modules=["query_proj", "value_proj", "key_proj"],
            bias="none",
        )
        model = get_peft_model(model, lora_config)
        trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
        total = sum(p.numel() for p in model.parameters())
        logger.info(
            "lora_applied",
            trainable_params=trainable,
            total_params=total,
            pct=f"{100 * trainable / total:.2f}%",
        )

        # ── Training output dir ──
        output_dir = str(TRAINING_DIR / f"{job.org_id}_{job.id}")
        job.output_dir = output_dir

        # ── Training arguments — optimized for RTX 5060 ──
        training_args = TrainingArguments(
            output_dir=output_dir,
            num_train_epochs=job.total_epochs,
            per_device_train_batch_size=16,
            per_device_eval_batch_size=32,
            learning_rate=2e-4,
            weight_decay=0.01,
            warmup_ratio=0.1,
            lr_scheduler_type="cosine",
            eval_strategy="epoch",
            save_strategy="epoch",
            save_total_limit=2,
            load_best_model_at_end=True,
            metric_for_best_model="f1_weighted",
            greater_is_better=True,
            bf16=torch.cuda.is_available(),  # RTX 5060 natively supports BF16 which prevents DeBERTa overflows
            fp16=False,
            dataloader_num_workers=2,
            logging_steps=10,
            report_to="none",
            seed=42,
        )

        # ── Metrics ──
        def compute_metrics(eval_pred):
            logits, labels_arr = eval_pred
            predictions = np.argmax(logits, axis=-1)
            acc = accuracy_score(labels_arr, predictions)
            precision, recall, f1, _ = precision_recall_fscore_support(
                labels_arr, predictions, average="weighted", zero_division=0,
            )
            return {
                "accuracy": acc,
                "precision": precision,
                "recall": recall,
                "f1_weighted": f1,
            }

        # ── Custom callback for progress ──
        from transformers import TrainerCallback

        class ProgressCallback(TrainerCallback):
            def on_epoch_end(self, args, state, control, **kwargs):
                job.current_epoch = int(state.epoch)
                job.progress = state.epoch / job.total_epochs
                if state.log_history:
                    latest = state.log_history[-1]
                    job.metrics = {
                        k: round(v, 4) if isinstance(v, float) else v
                        for k, v in latest.items()
                        if k in ("eval_accuracy", "eval_f1_weighted", "eval_precision", "eval_recall", "eval_loss", "loss")
                    }
                logger.info(
                    "training_epoch_complete",
                    job_id=job.id,
                    epoch=job.current_epoch,
                    metrics=job.metrics,
                )

        # ── Train ──
        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=train_ds,
            eval_dataset=val_ds,
            compute_metrics=compute_metrics,
            callbacks=[ProgressCallback(), EarlyStoppingCallback(early_stopping_patience=3)],
        )

        trainer.train()

        # ── Save best model ──
        best_dir = os.path.join(output_dir, "best_adapter")
        model.save_pretrained(best_dir)
        tokenizer.save_pretrained(best_dir)

        # Save metadata
        meta = {
            "job_id": job.id,
            "org_id": job.org_id,
            "base_model": job.base_model,
            "labels": labels,
            "label2id": label2id,
            "id2label": id2label,
            "num_labels": num_labels,
            "lora_r": 16,
            "lora_alpha": 32,
            "trainable_params": trainable,
            "total_params": total,
            "train_samples": len(train_records),
            "val_samples": len(val_records),
            "final_metrics": job.metrics,
            "created_at": job.created_at,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
        with open(os.path.join(best_dir, "training_meta.json"), "w") as f:
            json.dump(meta, f, indent=2)

        job.status = "completed"
        job.progress = 1.0
        job.completed_at = datetime.now(timezone.utc).isoformat()

        logger.info(
            "training_completed",
            job_id=job.id,
            metrics=job.metrics,
            output=best_dir,
        )

        return job

    except Exception as e:
        job.status = "failed"
        job.error = str(e)
        job.completed_at = datetime.now(timezone.utc).isoformat()
        logger.error("training_failed", job_id=job.id, error=str(e), exc_info=True)
        return job


def train_zero_day_embeddings(
    job: TrainingJob,
) -> TrainingJob:
    """
    Fine-tune a sentence-transformer for zero-day prompt embedding detection.
    
    Uses contrastive learning on (malicious, benign) prompt pairs.
    """
    try:
        job.status = "running"
        job.started_at = datetime.now(timezone.utc).isoformat()
        _active_jobs[job.id] = job

        logger.info("embedding_training_started", job_id=job.id)

        from sentence_transformers import SentenceTransformer, InputExample, losses
        from torch.utils.data import DataLoader

        device = get_device()

        # ── Load dataset (expects: {"text": ..., "label": 0|1}) ──
        records = []
        with open(job.dataset_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                records.append(json.loads(line))

        examples = []
        for r in records:
            # If dataset was pre-generated as pairs, just take the first text as a fallback
            if "text" in r:
                examples.append(InputExample(texts=[r["text"]], label=int(float(r["label"]))))
            elif "text_a" in r:
                examples.append(InputExample(texts=[r["text_a"]], label=int(float(r["label"]))))

        logger.info("embedding_dataset_loaded", samples=len(examples))

        # ── Load base sentence-transformer ──
        base_model = job.base_model or "sentence-transformers/all-mpnet-base-v2"
        model = SentenceTransformer(base_model, device=str(device), cache_folder=str(MODEL_CACHE))

        # ── Training ──
        model.max_seq_length = 256
        train_dataloader = DataLoader(examples, shuffle=True, batch_size=16)
        train_loss = losses.BatchHardTripletLoss(
            model=model,
            distance_metric=losses.BatchHardTripletLossDistanceFunction.cosine_distance
        )

        output_dir = str(TRAINING_DIR / f"embedding_{job.org_id}_{job.id}")
        job.output_dir = output_dir

        model.fit(
            train_objectives=[(train_dataloader, train_loss)],
            epochs=job.total_epochs,
            warmup_steps=int(0.1 * len(train_dataloader)),
            output_path=output_dir,
            show_progress_bar=True,
        )

        # Save metadata
        meta = {
            "job_id": job.id,
            "org_id": job.org_id,
            "base_model": base_model,
            "model_type": "zero_day_embedding",
            "train_pairs": len(examples),
            "epochs": job.total_epochs,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
        with open(os.path.join(output_dir, "training_meta.json"), "w") as f:
            json.dump(meta, f, indent=2)

        job.status = "completed"
        job.progress = 1.0
        job.completed_at = datetime.now(timezone.utc).isoformat()

        logger.info("embedding_training_completed", job_id=job.id, output=output_dir)
        return job

    except Exception as e:
        job.status = "failed"
        job.error = str(e)
        job.completed_at = datetime.now(timezone.utc).isoformat()
        logger.error("embedding_training_failed", job_id=job.id, error=str(e), exc_info=True)
        return job


# ── Job management ──

def get_job(job_id: str) -> Optional[TrainingJob]:
    return _active_jobs.get(job_id)


def list_jobs(org_id: Optional[str] = None) -> list[TrainingJob]:
    jobs = list(_active_jobs.values())
    if org_id and org_id != "None":
        jobs = [j for j in jobs if j.org_id == org_id]
    return sorted(jobs, key=lambda j: j.created_at, reverse=True)
