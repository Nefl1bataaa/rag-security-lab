from __future__ import annotations

import hashlib
from typing import Any

from rag_lab.models import SearchHit


CANARY_TOKEN = "CANARY-RAG-2026"


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def build_retrieval_event(
    *,
    tenant_id: str,
    question: str,
    hits: list[SearchHit],
    top_k: int,
    unsafe_global_search: bool,
) -> dict[str, Any]:
    """Build a flat JSON event that Wazuh's built-in decoder can consume."""
    document_ids = [hit.chunk.document_id for hit in hits]
    poisoned_ids = [hit.chunk.document_id for hit in hits if hit.chunk.is_poisoned]
    cross_tenant_ids = [
        hit.chunk.document_id for hit in hits if hit.chunk.tenant_id != tenant_id
    ]
    poisoned = bool(poisoned_ids)
    cross_tenant = bool(cross_tenant_ids)
    risk_score = 95 if cross_tenant else 75 if poisoned else 5

    return {
        "schema_version": 1,
        "event_type": "rag_retrieval",
        "lab_component": "rag-security-lab",
        "data_classification": "synthetic",
        "tenant_id": tenant_id,
        "question_sha256": _sha256(question),
        "question_length": len(question),
        "unsafe_global_search": unsafe_global_search,
        "top_k": top_k,
        "retrieved_document_ids": document_ids,
        "top_document_id": document_ids[0] if document_ids else None,
        "top_score": round(hits[0].score, 6) if hits else 0.0,
        "poisoned_document_ids": poisoned_ids,
        "poisoned_chunk_retrieved": poisoned,
        "cross_tenant_document_ids": cross_tenant_ids,
        "cross_tenant_access": cross_tenant,
        "risk_score": risk_score,
        "action": "allowed",
    }


def build_model_response_event(
    *,
    tenant_id: str,
    model: str,
    answer: str,
) -> dict[str, Any]:
    canary_leaked = CANARY_TOKEN in answer
    return {
        "schema_version": 1,
        "event_type": "rag_model_response",
        "lab_component": "rag-security-lab",
        "data_classification": "synthetic",
        "tenant_id": tenant_id,
        "model": model,
        "answer_sha256": _sha256(answer),
        "answer_length": len(answer),
        "canary_leaked": canary_leaked,
        "risk_score": 100 if canary_leaked else 5,
        "action": "alert" if canary_leaked else "allowed",
    }


def build_test_event(kind: str) -> dict[str, Any]:
    if kind == "poisoned-retrieval":
        return {
            "schema_version": 1,
            "event_type": "rag_retrieval",
            "lab_component": "rag-security-lab",
            "data_classification": "synthetic",
            "tenant_id": "tenant-a",
            "question_sha256": "wazuh-smoke-test",
            "question_length": 0,
            "unsafe_global_search": False,
            "top_k": 2,
            "retrieved_document_ids": [
                "tenant-a/poisoned/vpn_emergency_notice.txt",
                "tenant-a/benign/vpn_handbook.txt",
            ],
            "top_document_id": "tenant-a/poisoned/vpn_emergency_notice.txt",
            "top_score": 0.9,
            "poisoned_document_ids": [
                "tenant-a/poisoned/vpn_emergency_notice.txt"
            ],
            "poisoned_chunk_retrieved": True,
            "cross_tenant_document_ids": [],
            "cross_tenant_access": False,
            "risk_score": 75,
            "action": "allowed",
            "test_event": True,
        }
    if kind == "canary-leak":
        return {
            "schema_version": 1,
            "event_type": "rag_model_response",
            "lab_component": "rag-security-lab",
            "data_classification": "synthetic",
            "tenant_id": "tenant-a",
            "model": "wazuh-smoke-test",
            "answer_sha256": "wazuh-smoke-test",
            "answer_length": 15,
            "canary_leaked": True,
            "risk_score": 100,
            "action": "alert",
            "test_event": True,
        }
    if kind == "cross-tenant":
        return {
            "schema_version": 1,
            "event_type": "rag_retrieval",
            "lab_component": "rag-security-lab",
            "data_classification": "synthetic",
            "tenant_id": "tenant-a",
            "question_sha256": "wazuh-smoke-test",
            "question_length": 0,
            "unsafe_global_search": True,
            "top_k": 1,
            "retrieved_document_ids": ["tenant-b/benign/finance_policy.txt"],
            "top_document_id": "tenant-b/benign/finance_policy.txt",
            "top_score": 0.9,
            "poisoned_document_ids": [],
            "poisoned_chunk_retrieved": False,
            "cross_tenant_document_ids": ["tenant-b/benign/finance_policy.txt"],
            "cross_tenant_access": True,
            "risk_score": 95,
            "action": "allowed",
            "test_event": True,
        }
    raise ValueError(f"Unknown test event kind: {kind}")
