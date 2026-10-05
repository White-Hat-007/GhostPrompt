"""
GPU Training Pipeline

Detects GPU availability, trains custom classifiers for
prompt injection and jailbreak detection, and exports
optimized ONNX models for inference.
"""

import os
import json
from pathlib import Path
from typing import Optional
from app.core.config import get_settings
from app.core.logging import get_logger

settings = get_settings()
logger = get_logger("ml.gpu_training")


class GPUInfo:
    """GPU detection and information."""

    def __init__(self):
        self.cuda_available = False
        self.gpu_name = "None"
        self.gpu_count = 0
        self.vram_gb = 0.0
        self.driver_version = "N/A"

    def detect(self) -> dict:
        """Detect GPU availability and capabilities."""
        try:
            import torch
            self.cuda_available = torch.cuda.is_available()
            if self.cuda_available:
                self.gpu_count = torch.cuda.device_count()
                self.gpu_name = torch.cuda.get_device_name(0)
                self.vram_gb = round(
                    torch.cuda.get_device_properties(0).total_memory / (1024**3), 2
                )
                self.driver_version = torch.version.cuda or "N/A"
        except ImportError:
            logger.warning("pytorch_not_installed")
        except Exception as e:
            logger.warning("gpu_detection_failed", error=str(e))

        info = {
            "cuda_available": self.cuda_available,
            "gpu_name": self.gpu_name,
            "gpu_count": self.gpu_count,
            "vram_gb": self.vram_gb,
            "driver_version": self.driver_version,
        }
        logger.info("gpu_detected", **info)
        return info


class TrainingPipeline:
    """
    Training pipeline for custom threat detection classifiers.

    Supports:
    - Prompt injection classifier
    - Jailbreak classifier
    - Semantic anomaly detector
    - Fine-tuning on organization-specific data

    Optimized for consumer GPUs (RTX series) with automatic
    batch size and precision selection.
    """

    def __init__(self):
        self.gpu_info = GPUInfo()
        self.output_dir = Path(settings.TRAINING_OUTPUT_DIR)
        self.cache_dir = Path(settings.MODEL_CACHE_DIR)

    async def initialize(self) -> dict:
        """Initialize training pipeline and detect hardware."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        return self.gpu_info.detect()

    def get_training_config(self, model_type: str) -> dict:
        """Get optimized training configuration based on available hardware."""
        vram = self.gpu_info.vram_gb

        # Auto-configure based on VRAM
        if vram >= 24:
            batch_size, precision, max_length = 32, "fp16", 512
        elif vram >= 12:
            batch_size, precision, max_length = 16, "fp16", 384
        elif vram >= 8:
            batch_size, precision, max_length = 8, "fp16", 256
        elif vram >= 4:
            batch_size, precision, max_length = 4, "fp16", 128
        else:
            # CPU fallback
            batch_size, precision, max_length = 2, "fp32", 128

        base_models = {
            "prompt_injection": "distilbert-base-uncased",
            "jailbreak": "distilbert-base-uncased",
            "anomaly": "sentence-transformers/all-MiniLM-L6-v2",
            "semantic": "sentence-transformers/all-MiniLM-L6-v2",
        }

        return {
            "model_type": model_type,
            "base_model": base_models.get(model_type, "distilbert-base-uncased"),
            "batch_size": batch_size,
            "precision": precision,
            "max_length": max_length,
            "learning_rate": 2e-5,
            "epochs": 5,
            "warmup_steps": 100,
            "weight_decay": 0.01,
            "use_gpu": self.gpu_info.cuda_available,
            "output_dir": str(self.output_dir / model_type),
        }

    async def train_classifier(
        self,
        model_type: str,
        training_data: list[dict],
        validation_data: Optional[list[dict]] = None,
    ) -> dict:
        """
        Train a binary classifier for threat detection.

        training_data format: [{"text": "...", "label": 0|1}, ...]
        """
        config = self.get_training_config(model_type)
        logger.info("training_started", **config, samples=len(training_data))

        try:
            import torch
            from transformers import (
                AutoTokenizer, AutoModelForSequenceClassification,
                TrainingArguments, Trainer,
            )

            # Load model and tokenizer
            tokenizer = AutoTokenizer.from_pretrained(
                config["base_model"], cache_dir=str(self.cache_dir)
            )
            model = AutoModelForSequenceClassification.from_pretrained(
                config["base_model"], num_labels=2, cache_dir=str(self.cache_dir)
            )

            if config["use_gpu"]:
                model = model.cuda()

            # Prepare dataset
            texts = [d["text"] for d in training_data]
            labels = [d["label"] for d in training_data]

            encodings = tokenizer(
                texts,
                truncation=True,
                padding=True,
                max_length=config["max_length"],
                return_tensors="pt",
            )

            class SimpleDataset(torch.utils.data.Dataset):
                def __init__(self, encodings, labels):
                    self.encodings = encodings
                    self.labels = labels

                def __getitem__(self, idx):
                    item = {k: v[idx] for k, v in self.encodings.items()}
                    item["labels"] = torch.tensor(self.labels[idx])
                    return item

                def __len__(self):
                    return len(self.labels)

            train_dataset = SimpleDataset(encodings, labels)

            # Training arguments
            output_path = config["output_dir"]
            training_args = TrainingArguments(
                output_dir=output_path,
                num_train_epochs=config["epochs"],
                per_device_train_batch_size=config["batch_size"],
                warmup_steps=config["warmup_steps"],
                weight_decay=config["weight_decay"],
                logging_steps=10,
                save_strategy="epoch",
                fp16=config["precision"] == "fp16" and config["use_gpu"],
                report_to="none",
            )

            # Train
            trainer = Trainer(
                model=model,
                args=training_args,
                train_dataset=train_dataset,
            )
            train_result = trainer.train()

            # Save model
            model.save_pretrained(output_path)
            tokenizer.save_pretrained(output_path)

            # Export to ONNX
            onnx_path = None
            if settings.ONNX_OPTIMIZATION:
                onnx_path = await self._export_onnx(model, tokenizer, output_path, config)

            result = {
                "status": "completed",
                "model_type": model_type,
                "output_dir": output_path,
                "onnx_path": onnx_path,
                "training_loss": train_result.training_loss,
                "epochs": config["epochs"],
                "samples": len(training_data),
                "gpu_used": config["use_gpu"],
            }
            logger.info("training_completed", **result)
            return result

        except ImportError as e:
            error_msg = f"Missing dependency: {str(e)}. Install with: pip install torch transformers"
            logger.error("training_failed", error=error_msg)
            return {"status": "error", "error": error_msg}
        except Exception as e:
            logger.error("training_failed", error=str(e), exc_info=True)
            return {"status": "error", "error": str(e)}

    async def _export_onnx(
        self, model, tokenizer, output_dir: str, config: dict
    ) -> Optional[str]:
        """Export model to ONNX for optimized inference."""
        try:
            import torch

            onnx_path = os.path.join(output_dir, "model.onnx")
            dummy_input = tokenizer(
                "test input",
                return_tensors="pt",
                max_length=config["max_length"],
                padding="max_length",
                truncation=True,
            )

            if config["use_gpu"]:
                dummy_input = {k: v.cuda() for k, v in dummy_input.items()}

            torch.onnx.export(
                model,
                tuple(dummy_input.values()),
                onnx_path,
                input_names=list(dummy_input.keys()),
                output_names=["logits"],
                dynamic_axes={
                    name: {0: "batch_size"} for name in dummy_input.keys()
                },
                opset_version=14,
            )

            logger.info("onnx_export_completed", path=onnx_path)
            return onnx_path
        except Exception as e:
            logger.warning("onnx_export_failed", error=str(e))
            return None

    def list_trained_models(self) -> list[dict]:
        """List all trained models."""
        models = []
        if self.output_dir.exists():
            for model_dir in self.output_dir.iterdir():
                if model_dir.is_dir():
                    config_path = model_dir / "config.json"
                    has_onnx = (model_dir / "model.onnx").exists()
                    models.append({
                        "name": model_dir.name,
                        "path": str(model_dir),
                        "has_config": config_path.exists(),
                        "has_onnx": has_onnx,
                    })
        return models


# Singleton
training_pipeline = TrainingPipeline()
