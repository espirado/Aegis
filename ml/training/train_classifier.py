"""
AEGIS Layer 1 Classifier Training

Trains a 5-class prompt classifier (DistilBERT fine-tune) and exports to ONNX.

Classes:
    0 = benign
    1 = direct_injection
    2 = indirect_injection
    3 = jailbreak
    4 = phi_extraction

Usage:
    python ml/training/train_classifier.py \
        --train-path data/processed/train.jsonl \
        --val-path data/processed/val.jsonl \
        --output-dir ml/models/ \
        --epochs 10 \
        --seed 42
"""

import argparse
import json
import logging
from pathlib import Path

import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

NUM_CLASSES = 5
CLASS_NAMES = ["benign", "direct_injection", "indirect_injection", "jailbreak", "phi_extraction"]


class PromptDataset(Dataset):
    """Dataset for prompt classification."""

    def __init__(self, path: Path, tokenizer, max_len: int = 512):
        self.samples = []
        with open(path) as f:
            for line in f:
                record = json.loads(line)
                self.samples.append(record)
        self.tokenizer = tokenizer
        self.max_len = max_len
        logger.info(f"Loaded {len(self.samples)} samples from {path}")

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> dict:
        sample = self.samples[idx]
        encoding = self.tokenizer(
            sample["text"],
            max_length=self.max_len,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )
        return {
            "input_ids": encoding["input_ids"].squeeze(),
            "attention_mask": encoding["attention_mask"].squeeze(),
            "label": torch.tensor(sample["label"], dtype=torch.long),
        }


def train_epoch(model, dataloader, optimizer, criterion, device) -> float:
    """Train for one epoch, return average loss."""
    model.train()
    total_loss = 0.0
    for batch in dataloader:
        input_ids = batch["input_ids"].to(device)
        attention_mask = batch["attention_mask"].to(device)
        labels = batch["label"].to(device)

        optimizer.zero_grad()
        outputs = model(input_ids=input_ids, attention_mask=attention_mask)
        loss = criterion(outputs.logits, labels)
        loss.backward()
        optimizer.step()
        total_loss += loss.item()

    return total_loss / len(dataloader)


def evaluate(model, dataloader, device) -> dict:
    """Evaluate model, return metrics dict."""
    model.eval()
    all_preds = []
    all_labels = []

    with torch.no_grad():
        for batch in dataloader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["label"].to(device)

            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            preds = torch.argmax(outputs.logits, dim=-1)
            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())

    # TODO: Compute per-class F1, precision, recall
    # TODO: Compute confusion matrix
    # TODO: Compute FPR on benign class (critical metric — must be < 1%)
    # TODO: Compute ECE (expected calibration error)

    from sklearn.metrics import classification_report
    report = classification_report(
        all_labels, all_preds,
        target_names=CLASS_NAMES,
        output_dict=True,
    )

    fpr_benign = 1.0 - report["benign"]["recall"]  # Approximation
    logger.info(f"Benign FPR (approx): {fpr_benign:.4f}")

    return report


def export_onnx(model, tokenizer, output_path: Path, max_len: int = 512) -> None:
    """Export trained model to ONNX format."""
    model.eval()
    dummy_input = tokenizer(
        "Example clinical query about patient treatment",
        max_length=max_len,
        padding="max_length",
        truncation=True,
        return_tensors="pt",
    )

    torch.onnx.export(
        model,
        (dummy_input["input_ids"], dummy_input["attention_mask"]),
        str(output_path),
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch_size"},
            "attention_mask": {0: "batch_size"},
            "logits": {0: "batch_size"},
        },
        opset_version=14,
    )
    logger.info(f"ONNX model exported to {output_path}")

    # Validate exported model
    import onnxruntime as ort
    session = ort.InferenceSession(str(output_path))
    ort_inputs = {
        "input_ids": dummy_input["input_ids"].numpy(),
        "attention_mask": dummy_input["attention_mask"].numpy(),
    }
    ort_outputs = session.run(None, ort_inputs)
    logger.info(f"ONNX validation passed. Output shape: {ort_outputs[0].shape}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Train AEGIS Layer 1 classifier")
    parser.add_argument("--train-path", type=Path, required=True)
    parser.add_argument("--val-path", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("ml/models"))
    parser.add_argument("--epochs", type=int, default=10)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--lr", type=float, default=2e-5)
    parser.add_argument("--max-len", type=int, default=512)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--model-name", type=str, default="distilbert-base-uncased")
    args = parser.parse_args()

    torch.manual_seed(args.seed)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Device: {device}, Seed: {args.seed}")

    # TODO: Load tokenizer and model
    # from transformers import AutoTokenizer, AutoModelForSequenceClassification
    # tokenizer = AutoTokenizer.from_pretrained(args.model_name)
    # model = AutoModelForSequenceClassification.from_pretrained(
    #     args.model_name, num_labels=NUM_CLASSES
    # ).to(device)

    # TODO: Create datasets and dataloaders
    # TODO: Train loop with validation
    # TODO: Save best model checkpoint
    # TODO: Export to ONNX
    # TODO: Run calibration (Platt scaling / temperature scaling)
    # TODO: Save calibration parameters
    # TODO: Save metrics JSON with git commit hash

    logger.info("Training script skeleton — implement TODOs to run")


if __name__ == "__main__":
    main()
