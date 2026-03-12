#!/usr/bin/env python3
"""
AEGIS Data Preprocessing Pipeline

Transforms raw datasets into unified format for classifier training.

Output format (JSONL):
    {"text": "...", "label": 0, "source": "tensor_trust", "split": "train"}

Labels:
    0 = benign
    1 = direct_injection
    2 = indirect_injection
    3 = jailbreak
    4 = phi_extraction

Usage:
    python scripts/data/preprocess.py --data-dir data/raw --output-dir data/processed
"""

import argparse
import json
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

LABELS = {
    "benign": 0,
    "direct_injection": 1,
    "indirect_injection": 2,
    "jailbreak": 3,
    "phi_extraction": 4,
}


def process_tensor_trust(raw_dir: Path) -> list[dict]:
    """Process Tensor Trust injection attack/defense pairs."""
    tt_dir = raw_dir / "tensor-trust"
    if not tt_dir.exists():
        logger.warning(f"Tensor Trust not found at {tt_dir}, skipping")
        return []

    records = []
    # TODO: Parse Tensor Trust parquet/CSV files
    # Map attack prompts → direct_injection or jailbreak
    # Map defense prompts → benign
    logger.info(f"Processing Tensor Trust from {tt_dir}")

    # Placeholder — implement based on actual file format
    # for file in tt_dir.glob("*.parquet"):
    #     df = pd.read_parquet(file)
    #     for _, row in df.iterrows():
    #         records.append({
    #             "text": row["prompt"],
    #             "label": LABELS["direct_injection"],
    #             "source": "tensor_trust",
    #         })

    return records


def process_hackaprompt(raw_dir: Path) -> list[dict]:
    """Process HackAPrompt competition dataset."""
    ha_dir = raw_dir / "hackaprompt"
    if not ha_dir.exists():
        logger.warning(f"HackAPrompt not found at {ha_dir}, skipping")
        return []

    records = []
    logger.info(f"Processing HackAPrompt from {ha_dir}")

    # TODO: Parse HackAPrompt dataset
    # Classify by attack type: direct_injection, jailbreak, indirect_injection

    return records


def process_medqa(raw_dir: Path) -> list[dict]:
    """Process MedQA as benign clinical queries."""
    mq_dir = raw_dir / "medqa"
    if not mq_dir.exists():
        logger.warning(f"MedQA not found at {mq_dir}, skipping")
        return []

    records = []
    logger.info(f"Processing MedQA from {mq_dir}")

    # TODO: Parse MedQA USMLE questions
    # All queries labeled as benign (class 0)

    return records


def process_pubmedqa(raw_dir: Path) -> list[dict]:
    """Process PubMedQA as benign clinical queries."""
    pq_dir = raw_dir / "pubmedqa"
    if not pq_dir.exists():
        logger.warning(f"PubMedQA not found at {pq_dir}, skipping")
        return []

    records = []
    logger.info(f"Processing PubMedQA from {pq_dir}")

    # TODO: Parse PubMedQA questions
    # All queries labeled as benign (class 0)

    return records


def create_splits(
    records: list[dict],
    train_ratio: float = 0.8,
    val_ratio: float = 0.1,
    seed: int = 42,
) -> tuple[list[dict], list[dict], list[dict]]:
    """Stratified train/val/test split."""
    import random

    random.seed(seed)
    random.shuffle(records)

    n = len(records)
    train_end = int(n * train_ratio)
    val_end = int(n * (train_ratio + val_ratio))

    train = records[:train_end]
    val = records[train_end:val_end]
    test = records[val_end:]

    for r in train:
        r["split"] = "train"
    for r in val:
        r["split"] = "val"
    for r in test:
        r["split"] = "test"

    return train, val, test


def write_jsonl(records: list[dict], path: Path) -> None:
    """Write records as JSONL."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    logger.info(f"Wrote {len(records)} records to {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="AEGIS data preprocessing")
    parser.add_argument("--data-dir", type=Path, default=Path("data/raw"))
    parser.add_argument("--output-dir", type=Path, default=Path("data/processed"))
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    all_records = []
    all_records.extend(process_tensor_trust(args.data_dir))
    all_records.extend(process_hackaprompt(args.data_dir))
    all_records.extend(process_medqa(args.data_dir))
    all_records.extend(process_pubmedqa(args.data_dir))

    logger.info(f"Total records: {len(all_records)}")

    if not all_records:
        logger.error("No records processed. Download datasets first: make download-data")
        return

    # Label distribution
    from collections import Counter
    dist = Counter(r["label"] for r in all_records)
    for label_name, label_id in LABELS.items():
        logger.info(f"  {label_name} (class {label_id}): {dist.get(label_id, 0)}")

    # Split
    train, val, test = create_splits(all_records, seed=args.seed)
    logger.info(f"Split: train={len(train)}, val={len(val)}, test={len(test)}")

    # Write
    write_jsonl(train, args.output_dir / "train.jsonl")
    write_jsonl(val, args.output_dir / "val.jsonl")
    write_jsonl(test, args.output_dir / "test.jsonl")
    write_jsonl(all_records, args.output_dir / "all.jsonl")

    logger.info("Preprocessing complete.")


if __name__ == "__main__":
    main()
