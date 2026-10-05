"""
Real Dataset Loader for Hallucination Fine-Tuning
Downloads Kaggle and HuggingFace datasets and prepares them for PyTorch Trainer.
"""
import logging
import os
from pathlib import Path

from datasets import Dataset, load_dataset

logger = logging.getLogger(__name__)

# Kaggle credentials should be set via environment variables or ~/.kaggle/kaggle.json
# Do NOT hardcode credentials here
if not os.environ.get("KAGGLE_USERNAME"):
    logger.warning("KAGGLE_USERNAME not set — Kaggle dataset downloads will fail")
if not os.environ.get("KAGGLE_KEY"):
    logger.warning("KAGGLE_KEY not set — Kaggle dataset downloads will fail")

try:
    import kaggle
except ImportError:
    pass

def load_and_prepare_data():
    """
    Downloads datasets and formats them for NLI (Cross-Encoder) training.
    Required format: {"text": "premise [SEP] hypothesis", "label": 0/1}
    1 = Entailment (Faithful)
    0 = Contradiction (Hallucinated)
    """
    out_dir = Path("d:/PROJECTS/GhostPrompt/backend/app/ml/training/hallucination/data")
    out_dir.mkdir(parents=True, exist_ok=True)
    
    logger.info("Downloading Kaggle Dataset: sureshbeekhani/rag-based-hallucination-detection-dataset-for-llms")
    
    # Download via Kaggle API
    try:
        kaggle.api.dataset_download_files(
            "sureshbeekhani/rag-based-hallucination-detection-dataset-for-llms", 
            path=str(out_dir), 
            unzip=True
        )
    except Exception as e:
        logger.error(f"Failed to download Kaggle dataset: {e}")
        
    logger.info("Downloading HaluEval (Dialogue & QA) from HuggingFace...")
    # Load HaluEval standard benchmark for robust training
    try:
        halu_qa = load_dataset("pminervini/HaluEval", "qa", split="data[:5000]") # Subset to avoid OOM/time limits
        
        # Format HaluEval
        formatted_data = []
        for item in halu_qa:
            # item has 'knowledge' (context), 'question', 'right_answer', 'hallucinated_answer'
            ctx = item.get("knowledge", "")
            if not ctx: continue
            
            # Add positive example (Faithful)
            formatted_data.append({
                "text": f"{ctx} [SEP] {item['right_answer']}",
                "label": 1
            })
            
            # Add negative example (Hallucinated)
            formatted_data.append({
                "text": f"{ctx} [SEP] {item['hallucinated_answer']}",
                "label": 0
            })
            
        final_dataset = Dataset.from_list(formatted_data)
        final_dataset = final_dataset.train_test_split(test_size=0.1)
        
        logger.info(f"Prepared {len(formatted_data)} examples for training.")
        return final_dataset
    except Exception as e:
        logger.error(f"Failed to load HF dataset: {e}")
        return None

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    ds = load_and_prepare_data()
    print(ds)
