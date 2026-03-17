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
import time
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer, AutoModelForSequenceClassification

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

NUM_CLASSES = 5
CLASS_NAMES = ["benign", "direct_injection", "indirect_injection", "jailbreak", "phi_extraction"]


class PromptDataset(Dataset):
    """Dataset for prompt classification with upfront batch tokenization."""

    def __init__(self, path: Path, tokenizer, max_len: int = 128):
        samples = []
        with open(path) as f:
            for line in f:
                samples.append(json.loads(line))

        texts = [s["text"] for s in samples]
        labels = [s["label"] for s in samples]

        logger.info(f"Tokenizing {len(texts)} samples from {path}...")
        encodings = tokenizer(
            texts,
            max_length=max_len,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )
        self.input_ids = encodings["input_ids"]
        self.attention_mask = encodings["attention_mask"]
        self.labels = torch.tensor(labels, dtype=torch.long)
        logger.info(f"Loaded and tokenized {len(texts)} samples from {path}")

    def __len__(self) -> int:
        return len(self.labels)

    def __getitem__(self, idx: int) -> dict:
        return {
            "input_ids": self.input_ids[idx],
            "attention_mask": self.attention_mask[idx],
            "label": self.labels[idx],
        }


def train_epoch(model, dataloader, optimizer, criterion, device) -> float:
    """Train for one epoch, return average loss."""
    model.train()
    total_loss = 0.0
    num_batches = len(dataloader)
    for i, batch in enumerate(dataloader):
        input_ids = batch["input_ids"].to(device)
        attention_mask = batch["attention_mask"].to(device)
        labels = batch["label"].to(device)

        optimizer.zero_grad()
        outputs = model(input_ids=input_ids, attention_mask=attention_mask)
        loss = criterion(outputs.logits, labels)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
        optimizer.step()
        total_loss += loss.item()

        if (i + 1) % 50 == 0 or (i + 1) == num_batches:
            logger.info(f"  batch {i + 1}/{num_batches}, running_loss={total_loss / (i + 1):.4f}")

    return total_loss / num_batches


def evaluate(model, dataloader, device) -> dict:
    """Evaluate model, return metrics dict."""
    model.eval()
    all_preds = []
    all_labels = []
    all_probs = []

    with torch.no_grad():
        for batch in dataloader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["label"].to(device)

            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            probs = torch.softmax(outputs.logits, dim=-1)
            preds = torch.argmax(probs, dim=-1)

            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())
            all_probs.extend(probs.cpu().numpy())

    from sklearn.metrics import classification_report, confusion_matrix

    all_preds = np.array(all_preds)
    all_labels = np.array(all_labels)
    all_probs = np.array(all_probs)

    report = classification_report(
        all_labels, all_preds,
        target_names=CLASS_NAMES,
        output_dict=True,
        zero_division=0,
    )

    cm = confusion_matrix(all_labels, all_preds, labels=list(range(NUM_CLASSES)))

    benign_mask = all_labels == 0
    if benign_mask.sum() > 0:
        fpr_benign = (all_preds[benign_mask] != 0).mean()
    else:
        fpr_benign = 0.0
    logger.info(f"Benign FPR: {fpr_benign:.4f}")

    ece = _compute_ece(all_probs, all_labels, n_bins=10)
    logger.info(f"ECE: {ece:.4f}")

    report["fpr_benign"] = float(fpr_benign)
    report["ece"] = float(ece)
    report["confusion_matrix"] = cm.tolist()

    return report


def _compute_ece(probs: np.ndarray, labels: np.ndarray, n_bins: int = 10) -> float:
    """Compute Expected Calibration Error."""
    confidences = probs.max(axis=1)
    predictions = probs.argmax(axis=1)
    accuracies = (predictions == labels).astype(float)

    bin_boundaries = np.linspace(0, 1, n_bins + 1)
    ece = 0.0
    for i in range(n_bins):
        mask = (confidences > bin_boundaries[i]) & (confidences <= bin_boundaries[i + 1])
        if mask.sum() == 0:
            continue
        bin_acc = accuracies[mask].mean()
        bin_conf = confidences[mask].mean()
        ece += mask.sum() / len(labels) * abs(bin_acc - bin_conf)

    return ece


def export_onnx(model, tokenizer, output_path: Path, max_len: int = 128) -> None:
    """Export trained model to ONNX format."""
    model.eval()
    model.cpu()

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
    parser.add_argument("--max-len", type=int, default=128)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--model-name", type=str, default="prajjwal1/bert-tiny")
    args = parser.parse_args()

    torch.manual_seed(args.seed)
    np.random.seed(args.seed)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Device: {device}, Seed: {args.seed}")

    args.output_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"Loading tokenizer and model: {args.model_name}")
    tokenizer = AutoTokenizer.from_pretrained(args.model_name)
    model = AutoModelForSequenceClassification.from_pretrained(
        args.model_name, num_labels=NUM_CLASSES
    ).to(device)

    logger.info("Creating datasets...")
    train_dataset = PromptDataset(args.train_path, tokenizer, args.max_len)
    val_dataset = PromptDataset(args.val_path, tokenizer, args.max_len)

    train_loader = DataLoader(
        train_dataset, batch_size=args.batch_size, shuffle=True, num_workers=0
    )
    val_loader = DataLoader(
        val_dataset, batch_size=args.batch_size, shuffle=False, num_workers=0
    )

    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=0.01)
    criterion = nn.CrossEntropyLoss()

    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
        optimizer, T_max=args.epochs, eta_min=1e-6
    )

    best_val_acc = 0.0
    best_epoch = -1
    train_start = time.time()

    for epoch in range(args.epochs):
        epoch_start = time.time()
        train_loss = train_epoch(model, train_loader, optimizer, criterion, device)
        scheduler.step()

        val_report = evaluate(model, val_loader, device)
        val_acc = val_report["accuracy"]
        val_fpr = val_report["fpr_benign"]
        epoch_time = time.time() - epoch_start

        logger.info(
            f"Epoch {epoch + 1}/{args.epochs} — "
            f"loss: {train_loss:.4f}, val_acc: {val_acc:.4f}, "
            f"val_fpr: {val_fpr:.4f}, time: {epoch_time:.1f}s"
        )

        if val_acc > best_val_acc:
            best_val_acc = val_acc
            best_epoch = epoch + 1
            checkpoint_path = args.output_dir / "best_checkpoint.pt"
            torch.save({
                "epoch": epoch,
                "model_state_dict": model.state_dict(),
                "optimizer_state_dict": optimizer.state_dict(),
                "val_acc": val_acc,
                "val_report": val_report,
            }, checkpoint_path)
            logger.info(f"New best model saved (val_acc={val_acc:.4f})")

    total_time = time.time() - train_start
    logger.info(f"Training complete in {total_time:.1f}s. Best epoch: {best_epoch} (acc={best_val_acc:.4f})")

    logger.info("Loading best checkpoint for export...")
    checkpoint = torch.load(args.output_dir / "best_checkpoint.pt", weights_only=False)
    model.load_state_dict(checkpoint["model_state_dict"])

    onnx_path = args.output_dir / "classifier_v1.onnx"
    export_onnx(model, tokenizer, onnx_path, args.max_len)

    final_report = evaluate(model, val_loader, device)
    metrics = {
        "model_name": args.model_name,
        "epochs": args.epochs,
        "best_epoch": best_epoch,
        "best_val_acc": best_val_acc,
        "final_report": final_report,
        "training_time_s": total_time,
        "device": str(device),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    metrics_path = args.output_dir / "training_metrics.json"
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)
    logger.info(f"Training metrics saved to {metrics_path}")

    print("\n" + "=" * 60)
    print("AEGIS CLASSIFIER TRAINING COMPLETE")
    print("=" * 60)
    print(f"  Best val accuracy:  {best_val_acc:.4f}")
    print(f"  Benign FPR:         {final_report['fpr_benign']:.4f}  (target: < 0.01)")
    print(f"  ECE:                {final_report['ece']:.4f}  (target: < 0.05)")
    print(f"  ONNX model:         {onnx_path}")
    print(f"  Training time:      {total_time:.1f}s")
    print("=" * 60)


if __name__ == "__main__":
    main()
