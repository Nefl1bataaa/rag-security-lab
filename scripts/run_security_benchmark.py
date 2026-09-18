#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from rag_lab.benchmark import run_security_benchmark


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare RAG security policy modes.")
    parser.add_argument("--corpus", type=Path, default=ROOT / "data" / "corpus")
    parser.add_argument("--quarantine", type=Path, default=ROOT / "data" / "quarantine")
    parser.add_argument(
        "--dataset", type=Path, default=ROOT / "data" / "eval" / "security_cases.json"
    )
    parser.add_argument(
        "--modes",
        nargs="+",
        choices=["off", "audit", "enforce"],
        default=["off", "audit", "enforce"],
    )
    parser.add_argument("--top-k", type=int, default=2)
    parser.add_argument("--with-model", action="store_true")
    parser.add_argument(
        "--model-modes",
        nargs="+",
        choices=["off", "audit", "enforce"],
        default=["off", "enforce"],
    )
    parser.add_argument("--endpoint", default="http://127.0.0.1:11434")
    parser.add_argument("--model", default="qwen2.5:0.5b")
    parser.add_argument(
        "--output", type=Path, default=ROOT / "reports" / "security-benchmark.json"
    )
    args = parser.parse_args()

    report = run_security_benchmark(
        corpus_dir=args.corpus,
        quarantine_dir=args.quarantine,
        dataset_path=args.dataset,
        modes=args.modes,
        top_k=args.top_k,
        with_model=args.with_model,
        model_modes=args.model_modes,
        endpoint=args.endpoint,
        model=args.model,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"report_saved={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
