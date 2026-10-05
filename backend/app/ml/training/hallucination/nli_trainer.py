"""
Real NLI Entailment Model Trainer
Fine-tunes cross-encoder/nli-deberta-v3-base using GPU acceleration.
"""
import logging
import os
import sys

import evaluate
import numpy as np
import torch
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    Trainer,
    TrainingArguments,
)

# Import our data loader
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from data_loader import load_and_prepare_data

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def compute_metrics(eval_pred):
    metric = evaluate.load("accuracy")
    logits, labels = eval_pred
    predictions = np.argmax(logits, axis=-1)
    return metric.compute(predictions=predictions, references=labels)

def train_nli_model():
    logger.info("Checking hardware compatibility...")
    if not torch.cuda.is_available():
        logger.error("CUDA is NOT available! You cannot train this model efficiently on CPU.")
        logger.error("Aborting to prevent system freeze.")
        return
        
    device = torch.device("cuda")
    logger.info(f"GPU Detected: {torch.cuda.get_device_name(0)}")
    logger.info(f"Available VRAM: {torch.cuda.get_device_properties(0).total_memory / 1024**3:.2f} GB")
    
    # 1. Load Data
    logger.info("Loading datasets via Kaggle and HuggingFace...")
    dataset = load_and_prepare_data()
    if not dataset:
        logger.error("Failed to load dataset. Aborting.")
        return
        
    # 2. Load Tokenizer & Model
    model_name = "cross-encoder/nli-deberta-v3-base"
    logger.info(f"Loading tokenizer and model: {model_name}")
    
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    # The base model outputs 3 labels: [contradiction, neutral, entailment]
    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=3, ignore_mismatched_sizes=True).to(device)
    
    # 3. Tokenize Data
    def tokenize_function(examples):
        # The text is already formatted as "Premise [SEP] Hypothesis"
        return tokenizer(examples["text"], padding="max_length", truncation=True, max_length=256)
        
    logger.info("Tokenizing datasets...")
    tokenized_datasets = dataset.map(tokenize_function, batched=True)
    
    # 4. Configure Training Arguments (Optimized for Laptop GPU)
    output_dir = "d:/PROJECTS/GhostPrompt/backend/models/hallucination/nli_finetuned"
    
    training_args = TrainingArguments(
        output_dir=output_dir,
        eval_strategy="epoch",
        learning_rate=2e-5,
        per_device_train_batch_size=4,  # Small to prevent OOM
        per_device_eval_batch_size=4,
        gradient_accumulation_steps=4,  # Effective batch size 16
        num_train_epochs=2,             # Keep it short for the laptop
        weight_decay=0.01,
        fp16=True,                      # Crucial for VRAM optimization
        save_strategy="epoch",
        logging_dir="d:/PROJECTS/GhostPrompt/backend/logs/training",
        logging_steps=50,
        report_to="none"
    )
    
    # 5. Initialize Trainer
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_datasets["train"],
        eval_dataset=tokenized_datasets["test"],
        compute_metrics=compute_metrics,
    )
    
    # 6. TRAIN!
    logger.info("========================================")
    logger.info("🔥 STARTING GPU TRAINING LOOP 🔥")
    logger.info("========================================")
    
    trainer.train()
    
    logger.info("Training complete! Saving final model...")
    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)
    logger.info(f"Model successfully saved to: {output_dir}")

if __name__ == "__main__":
    train_nli_model()
