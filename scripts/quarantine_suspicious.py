#!/usr/bin/env python3
"""Compatibility wrapper for enforcing the integrated ingestion policy."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from rag_lab.policy import apply_ingestion_policy, scan_corpus


CORPUS = ROOT / "data" / "corpus"
QUARANTINE = ROOT / "data" / "quarantine"
AUDIT_LOG = ROOT / "logs" / "audit.jsonl"


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan or quarantine suspicious RAG documents.")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.dry_run:
        findings = scan_corpus(CORPUS)
        for finding in findings:
            print(
                f"SUSPICIOUS {finding.document_id} "
                f"signatures={','.join(finding.signatures)}"
            )
        print(f"scan_complete quarantined=0 dry_run=true findings={len(findings)}")
        return 0

    result = apply_ingestion_policy(
        corpus_dir=CORPUS,
        quarantine_dir=QUARANTINE,
        audit_log=AUDIT_LOG,
        mode="enforce",
    )
    for finding, destination in zip(result.findings, result.quarantine_paths):
        print(f"SUSPICIOUS {finding.document_id} signatures={','.join(finding.signatures)}")
        print(f"QUARANTINED -> {destination.relative_to(ROOT).as_posix()}")
    print(
        "scan_complete "
        f"quarantined={result.quarantined_document_count} dry_run=false "
        f"findings={result.suspicious_document_count}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
