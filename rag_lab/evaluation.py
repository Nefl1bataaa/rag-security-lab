from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rag_lab.index import TfidfIndex


def evaluate(index: TfidfIndex, dataset_path: Path, top_k: int) -> dict[str, Any]:
    cases = json.loads(dataset_path.read_text(encoding="utf-8"))
    results = []
    poison_cases = 0
    poison_hits = 0
    benign_cases = 0
    benign_poison_exposures = 0
    expected_doc_hits = 0
    cross_tenant_leaks = 0

    for case in cases:
        hits = index.search(case["question"], tenant_id=case["tenant_id"], top_k=top_k)
        poison_hit = any(hit.chunk.is_poisoned for hit in hits)
        if case.get("attack_case", False):
            poison_cases += 1
            poison_hits += int(poison_hit)
        else:
            benign_cases += 1
            benign_poison_exposures += int(poison_hit)

        expected_document = case.get("expected_document")
        expected_hit = expected_document is None or any(
            hit.chunk.document_id == expected_document for hit in hits
        )
        expected_doc_hits += int(expected_hit)
        cross_tenant_leaks += sum(
            hit.chunk.tenant_id != case["tenant_id"] for hit in hits
        )
        results.append(
            {
                "case_id": case["case_id"],
                "question": case["question"],
                "poison_hit": poison_hit,
                "expected_document_hit": expected_hit,
                "documents": [hit.chunk.document_id for hit in hits],
            }
        )

    return {
        "case_count": len(cases),
        "top_k": top_k,
        "poisoned_retrieval_hit_rate": round(poison_hits / poison_cases, 4)
        if poison_cases
        else None,
        "benign_poison_exposure_rate": round(benign_poison_exposures / benign_cases, 4)
        if benign_cases
        else None,
        "expected_document_hit_rate": round(expected_doc_hits / len(cases), 4)
        if cases
        else None,
        "cross_tenant_leak_count": cross_tenant_leaks,
        "results": results,
    }
