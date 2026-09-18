#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

sudo apt-get update
sudo apt-get install -y python3 python3-venv git curl jq open-vm-tools

cd "$PROJECT_DIR"
python3 -m venv .venv
source .venv/bin/activate

python -m rag_lab ingest --policy off
python -m rag_lab evaluate
python -m unittest discover -s tests -v

printf '\nBaseline ready. Activate later with:\n  source %s/.venv/bin/activate\n' "$PROJECT_DIR"
