#!/usr/bin/env bash
# AEGIS Dataset Download Script
# Downloads all public datasets required for training and evaluation.
# MIMIC-III requires separate credentials — see download_mimic.sh
#
# Usage: ./scripts/data/download_all.sh [--force]
#
# Datasets:
#   1. Tensor Trust    — Injection attack/defense pairs
#   2. HackAPrompt     — Competition-sourced injection strategies  
#   3. MedQA           — Medical QA (benign clinical queries for FPR testing)
#   4. PubMedQA        — Biomedical QA (benign clinical queries for FPR testing)
#   5. CICIoMT2024     — IoMT attack categories (manual download required)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DATA_DIR="$PROJECT_ROOT/data/raw"
FORCE="${1:-}"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
err() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*" >&2; }

check_deps() {
    for cmd in git wget python3 unzip; do
        if ! command -v "$cmd" &>/dev/null; then
            err "Required command not found: $cmd"
            exit 1
        fi
    done
}

skip_if_exists() {
    local dir="$1"
    if [[ -d "$dir" && "$FORCE" != "--force" ]]; then
        log "SKIP: $dir already exists (use --force to re-download)"
        return 0
    fi
    return 1
}

# ─────────────────────────────────────────────────────────
# 1. Tensor Trust
# Source: https://tensortrust.ai/dataset
# Paper: Toyer et al. (2023) — Interpretable prompt injection attacks
# ─────────────────────────────────────────────────────────
download_tensor_trust() {
    local dest="$DATA_DIR/tensor-trust"
    if skip_if_exists "$dest"; then return; fi

    log "Downloading Tensor Trust dataset..."
    mkdir -p "$dest"

    # The dataset is available via HuggingFace
    python3 -c "
from huggingface_hub import snapshot_download
snapshot_download(
    repo_id='ethz-spylab/tensor-trust-data',
    repo_type='dataset',
    local_dir='$dest',
    local_dir_use_symlinks=False,
)
print('Tensor Trust download complete.')
"
    log "DONE: Tensor Trust → $dest"
}

# ─────────────────────────────────────────────────────────
# 2. HackAPrompt
# Source: https://huggingface.co/datasets/hackaprompt/hackaprompt-dataset
# Paper: Competition-sourced injection strategies
# ─────────────────────────────────────────────────────────
download_hackaprompt() {
    local dest="$DATA_DIR/hackaprompt"
    if skip_if_exists "$dest"; then return; fi

    log "Downloading HackAPrompt dataset..."
    mkdir -p "$dest"

    python3 -c "
from huggingface_hub import snapshot_download
snapshot_download(
    repo_id='hackaprompt/hackaprompt-dataset',
    repo_type='dataset',
    local_dir='$dest',
    local_dir_use_symlinks=False,
)
print('HackAPrompt download complete.')
"
    log "DONE: HackAPrompt → $dest"
}

# ─────────────────────────────────────────────────────────
# 3. MedQA
# Source: https://github.com/jind11/MedQA
# Purpose: Benign clinical queries — must NOT trigger false positives
# ─────────────────────────────────────────────────────────
download_medqa() {
    local dest="$DATA_DIR/medqa"
    if skip_if_exists "$dest"; then return; fi

    log "Downloading MedQA dataset..."
    mkdir -p "$dest"

    # MedQA is distributed via Google Drive / GitHub releases
    git clone --depth 1 https://github.com/jind11/MedQA.git "$dest/repo"
    
    # Extract the USMLE subset (English, most relevant)
    if [[ -d "$dest/repo/data_clean/questions/US" ]]; then
        cp -r "$dest/repo/data_clean/questions/US" "$dest/usmle"
        log "Extracted USMLE subset"
    else
        log "WARN: Expected MedQA directory structure not found. Check $dest/repo/"
    fi

    log "DONE: MedQA → $dest"
}

# ─────────────────────────────────────────────────────────
# 4. PubMedQA
# Source: https://pubmedqa.github.io/
# Purpose: Biomedical QA — benign queries for FPR calibration
# ─────────────────────────────────────────────────────────
download_pubmedqa() {
    local dest="$DATA_DIR/pubmedqa"
    if skip_if_exists "$dest"; then return; fi

    log "Downloading PubMedQA dataset..."
    mkdir -p "$dest"

    git clone --depth 1 https://github.com/pubmedqa/pubmedqa.git "$dest/repo"

    log "DONE: PubMedQA → $dest"
}

# ─────────────────────────────────────────────────────────
# 5. CICIoMT2024
# Source: https://www.unb.ca/cic/datasets/iomt-dataset-2024.html
# Note: Requires manual download from UNB website
# ─────────────────────────────────────────────────────────
download_ciciomt() {
    local dest="$DATA_DIR/ciciomt2024"
    if skip_if_exists "$dest"; then return; fi

    mkdir -p "$dest"
    cat > "$dest/DOWNLOAD_INSTRUCTIONS.md" << 'EOF'
# CICIoMT2024 Dataset

This dataset requires manual download from the University of New Brunswick.

## Steps:
1. Go to https://www.unb.ca/cic/datasets/iomt-dataset-2024.html
2. Fill out the dataset request form
3. Download the dataset files
4. Extract to this directory: data/raw/ciciomt2024/

## Reference:
Dacosta, L. P., et al. (2024). CICIoMT2024: Benchmark dataset for IoMT security.
Internet of Things, 28, 101377.
EOF

    log "MANUAL: CICIoMT2024 requires manual download. See $dest/DOWNLOAD_INSTRUCTIONS.md"
}

# ─────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────
main() {
    log "AEGIS Dataset Download"
    log "======================"
    log "Data directory: $DATA_DIR"
    
    check_deps
    mkdir -p "$DATA_DIR"

    download_tensor_trust
    download_hackaprompt
    download_medqa
    download_pubmedqa
    download_ciciomt

    log ""
    log "Download summary:"
    log "  Tensor Trust:  $DATA_DIR/tensor-trust/"
    log "  HackAPrompt:   $DATA_DIR/hackaprompt/"
    log "  MedQA:         $DATA_DIR/medqa/"
    log "  PubMedQA:      $DATA_DIR/pubmedqa/"
    log "  CICIoMT2024:   MANUAL DOWNLOAD REQUIRED"
    log "  MIMIC-III:     Run 'make download-mimic' separately"
    log ""
    log "Next: Run preprocessing with 'make preprocess-data'"
}

main "$@"
