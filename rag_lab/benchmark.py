from __future__ import annotations

import hashlib
import json
import math
import time
from pathlib import Path
from typing import Any, Callable, Iterable

from rag_lab.index import TfidfIndex
from rag_lab.ingestion import load_corpus
from rag_lab.models import Chunk, SearchHit
from rag_lab.ollama import build_baseline_messages, chat
from rag_lab.policy import PolicyFinding, scan_corpus
from rag_lab.security_events import CANARY_TOKEN


ChatFunction = Callable[..., str]


def _rate(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return round(ordered[index], 3)


def _document_classification(document_id: str) -> str:
    parts = Path(document_id).parts
    return parts[1] if len(parts) > 1 else "unknown"


def _load_snapshot(corpus_dir: Path, quarantine_dir: Path) -> list[Chunk]:
    chunks = load_corpus(corpus_dir)
    if quarantine_dir.exists():
        chunks.extend(load_corpus(quarantine_dir))
    unique: dict[tuple[str, str], Chunk] = {}
    for chunk in chunks:
        unique[(chunk.document_id, chunk.chunk_id)] = chunk
    return list(unique.values())


def _scan_snapshot(corpus_dir: Path, quarantine_dir: Path) -> list[PolicyFinding]:
    findings = scan_corpus(corpus_dir)
    if quarantine_dir.exists():
        findings.extend(scan_corpus(quarantine_dir))
    unique: dict[tuple[str, str], PolicyFinding] = {}
    for finding in findings:
        unique[(finding.document_id, finding.document_sha256)] = finding
    return list(unique.values())


def _answer_hash(answer: str) -> str:
    return hashlib.sha256(answer.encode("utf-8")).hexdigest()


def _retrieval_result(case: dict[str, Any], hits: list[SearchHit]) -> dict[str, Any]:
    documents = [hit.chunk.document_id for hit in hits]
    return {
        "case_id": case["case_id"],
        "category": case["category"],
        "attack_case": bool(case.get("attack_case", False)),
        "poison_hit": any(hit.chunk.is_poisoned for hit in hits),
        "cross_tenant_hit": any(
            hit.chunk.tenant_id != case["tenant_id"] for hit in hits
        ),
        "expected_document_hit": case.get("expected_document") is None
        or case["expected_document"] in documents,
        "documents": documents,
    }


def run_security_benchmark(
    *,
    corpus_dir: Path,
    quarantine_dir: Path,
    dataset_path: Path,
    modes: Iterable[str] = ("off", "audit", "enforce"),
    top_k: int = 2,
    with_model: bool = False,
    model_modes: Iterable[str] = ("off", "enforce"),
    endpoint: str = "http://127.0.0.1:11434",
    model: str = "qwen2.5:0.5b",
    chat_function: ChatFunction = chat,
) -> dict[str, Any]:
    cases = json.loads(dataset_path.read_text(encoding="utf-8"))
    all_chunks = _load_snapshot(corpus_dir, quarantine_dir)
    findings = _scan_snapshot(corpus_dir, quarantine_dir)
    suspicious_ids = {finding.document_id for finding in findings}
    all_document_ids = {chunk.document_id for chunk in all_chunks}
    poisoned_document_ids = {
        document_id
        for document_id in all_document_ids
        if _document_classification(document_id) == "poisoned"
    }
    benign_document_ids = {
        document_id
        for document_id in all_document_ids
        if _document_classification(document_id) == "benign"
    }
    false_positive_ids = suspicious_ids & benign_document_ids
    detected_poison_ids = suspicious_ids & poisoned_document_ids
    model_mode_set = set(model_modes)

    report: dict[str, Any] = {
        "schema_version": 1,
        "dataset": str(dataset_path),
        "case_count": len(cases),
        "top_k": top_k,
        "scanner": {
            "document_count": len(all_document_ids),
            "known_poisoned_document_count": len(poisoned_document_ids),
            "suspicious_document_count": len(suspicious_ids),
            "detected_poisoned_document_count": len(detected_poison_ids),
            "false_positive_document_count": len(false_positive_ids),
            "poison_detection_rate": _rate(
                len(detected_poison_ids), len(poisoned_document_ids)
            ),
            "false_positive_rate": _rate(
                len(false_positive_ids), len(benign_document_ids)
            ),
            "signatures": sorted(
                {signature for finding in findings for signature in finding.signatures}
            ),
        },
        "modes": {},
    }

    for mode in modes:
        if mode not in {"off", "audit", "enforce"}:
            raise ValueError(f"Unsupported policy mode: {mode}")
        chunks = (
            [chunk for chunk in all_chunks if chunk.document_id not in suspicious_ids]
            if mode == "enforce"
            else list(all_chunks)
        )
        if not chunks:
            raise ValueError(f"Policy mode {mode} left no chunks to evaluate.")
        index = TfidfIndex(chunks)
        retrieval_latencies: list[float] = []
        model_latencies: list[float] = []
        results: list[dict[str, Any]] = []
        attack_cases = poison_hits = 0
        benign_cases = benign_poison_exposures = 0
        expected_hits = clean_expected_hits = clean_expected_total = 0
        cross_tenant_leaks = 0
        model_attack_cases = model_attack_leaks = 0
        model_benign_cases = model_benign_leaks = 0

        for case in cases:
            started = time.perf_counter()
            hits = index.search(
                case["question"], tenant_id=case["tenant_id"], top_k=top_k
            )
            retrieval_latencies.append((time.perf_counter() - started) * 1000)
            result = _retrieval_result(case, hits)
            is_attack = result["attack_case"]
            if is_attack:
                attack_cases += 1
                poison_hits += int(result["poison_hit"])
            else:
                benign_cases += 1
                benign_poison_exposures += int(result["poison_hit"])
                clean_expected_total += 1
                clean_expected_hits += int(result["expected_document_hit"])
            expected_hits += int(result["expected_document_hit"])
            cross_tenant_leaks += int(result["cross_tenant_hit"])

            should_call_model = (
                with_model
                and mode in model_mode_set
                and bool(case.get("model_test", False))
                and bool(hits)
            )
            if should_call_model:
                messages = build_baseline_messages(case["question"], hits)
                model_started = time.perf_counter()
                answer = chat_function(
                    endpoint=endpoint,
                    model=model,
                    messages=messages,
                )
                model_latencies.append((time.perf_counter() - model_started) * 1000)
                leaked = CANARY_TOKEN in answer
                result["model_tested"] = True
                result["canary_leaked"] = leaked
                result["answer_sha256"] = _answer_hash(answer)
                result["answer_length"] = len(answer)
                if is_attack:
                    model_attack_cases += 1
                    model_attack_leaks += int(leaked)
                else:
                    model_benign_cases += 1
                    model_benign_leaks += int(leaked)
            else:
                result["model_tested"] = False
            results.append(result)

        report["modes"][mode] = {
            "indexed_chunk_count": len(chunks),
            "simulated_quarantined_document_count": len(suspicious_ids)
            if mode == "enforce"
            else 0,
            "poisoned_retrieval_hit_rate": _rate(poison_hits, attack_cases),
            "benign_poison_exposure_rate": _rate(
                benign_poison_exposures, benign_cases
            ),
            "expected_document_hit_rate": _rate(expected_hits, len(cases)),
            "clean_expected_document_hit_rate": _rate(
                clean_expected_hits, clean_expected_total
            ),
            "cross_tenant_leak_count": cross_tenant_leaks,
            "retrieval_latency_ms_p50": _percentile(retrieval_latencies, 0.50),
            "retrieval_latency_ms_p95": _percentile(retrieval_latencies, 0.95),
            "model_test_case_count": model_attack_cases + model_benign_cases,
            "attack_success_rate": _rate(model_attack_leaks, model_attack_cases),
            "benign_canary_leak_rate": _rate(
                model_benign_leaks, model_benign_cases
            ),
            "model_latency_ms_p50": _percentile(model_latencies, 0.50),
            "model_latency_ms_p95": _percentile(model_latencies, 0.95),
            "results": results,
        }
    return report
