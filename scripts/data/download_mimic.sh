#!/usr/bin/env bash
# MIMIC-III Download Script
# Requires PhysioNet credentials. See CONTRIBUTING.md for access instructions.
#
# Prerequisites:
#   1. Register at https://physionet.org/
#   2. Complete CITI "Data or Specimens Only Research" training
#   3. Request access to MIMIC-III Clinical Database
#   4. Set environment variables:
#      export PHYSIONET_USER="your_username"
#      export PHYSIONET_PASS="your_password"
#
# Usage: ./scripts/data/download_mimic.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DATA_DIR="$PROJECT_ROOT/data/raw/mimic-iii"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
err() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*" >&2; }

if [[ -z "${PHYSIONET_USER:-}" || -z "${PHYSIONET_PASS:-}" ]]; then
    err "PHYSIONET_USER and PHYSIONET_PASS environment variables required."
    err ""
    err "Setup instructions:"
    err "  1. Register at https://physionet.org/"
    err "  2. Complete CITI training"
    err "  3. Request MIMIC-III access"
    err "  4. export PHYSIONET_USER=your_username"
    err "  5. export PHYSIONET_PASS=your_password"
    exit 1
fi

if [[ -d "$DATA_DIR" && -f "$DATA_DIR/NOTEEVENTS.csv.gz" ]]; then
    log "MIMIC-III already downloaded at $DATA_DIR"
    log "Use --force to re-download"
    exit 0
fi

mkdir -p "$DATA_DIR"

log "Downloading MIMIC-III Clinical Database..."
log "This may take a while (several GB)..."

# We only need specific tables for PHI NER training:
#   NOTEEVENTS.csv.gz — clinical notes (primary training data)
#   PATIENTS.csv.gz   — patient demographics (for synthetic PHI generation)
#   ADMISSIONS.csv.gz  — admission records

MIMIC_URL="https://physionet.org/files/mimiciii/1.4"

for table in NOTEEVENTS PATIENTS ADMISSIONS; do
    log "Downloading ${table}.csv.gz ..."
    wget -q --user="$PHYSIONET_USER" --password="$PHYSIONET_PASS" \
        -O "$DATA_DIR/${table}.csv.gz" \
        "${MIMIC_URL}/${table}.csv.gz" || {
        err "Failed to download ${table}. Check credentials and access."
        exit 1
    }
done

log "DONE: MIMIC-III tables downloaded to $DATA_DIR"
log ""
log "IMPORTANT: Do NOT commit this data. It is gitignored."
log "IMPORTANT: Do NOT share these files. MIMIC-III license prohibits redistribution."
