#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

if [[ ! -d .venv ]]; then
  echo "Missing .venv. Run: bash scripts/bootstrap_ubuntu.sh" >&2
  exit 1
fi

source .venv/bin/activate
python -m rag_lab ingest --policy off
python -m rag_lab evaluate
python -m rag_lab query \
  --tenant tenant-a \
  --question "VPN 客户端连接故障，有没有紧急恢复说明？" \
  --top-k 2
