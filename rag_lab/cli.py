from __future__ import annotations

import argparse
import json
from pathlib import Path

from rag_lab.audit import write_event
from rag_lab.evaluation import evaluate
from rag_lab.index import TfidfIndex
from rag_lab.ingestion import load_corpus, load_index, save_index
from rag_lab.ollama import build_baseline_messages, chat
from rag_lab.policy import apply_ingestion_policy
from rag_lab.security_events import (
    build_model_response_event,
    build_retrieval_event,
    build_test_event,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS = PROJECT_ROOT / "data" / "corpus"
DEFAULT_QUARANTINE = PROJECT_ROOT / "data" / "quarantine"
DEFAULT_INDEX = PROJECT_ROOT / "storage" / "index.json"
DEFAULT_LOG = PROJECT_ROOT / "logs" / "audit.jsonl"
DEFAULT_DATASET = PROJECT_ROOT / "data" / "eval" / "retrieval_cases.json"


def _load_search_index(index_path: Path) -> TfidfIndex:
    if not index_path.exists():
        raise SystemExit("Index not found. Run `python -m rag_lab ingest` first.")
    return TfidfIndex(load_index(index_path))


def command_ingest(args: argparse.Namespace) -> None:
    policy = apply_ingestion_policy(
        corpus_dir=args.corpus,
        quarantine_dir=args.quarantine,
        audit_log=args.log,
        mode=args.policy,
    )
    chunks = load_corpus(args.corpus)
    save_index(chunks, args.index)
    poisoned = sum(chunk.is_poisoned for chunk in chunks)
    print(
        json.dumps(
            {
                "status": "ok",
                "policy_mode": policy.mode,
                "suspicious_document_count": policy.suspicious_document_count,
                "quarantined_document_count": policy.quarantined_document_count,
                "chunk_count": len(chunks),
                "poisoned_chunk_count": poisoned,
                "index": str(args.index),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


def _search(args: argparse.Namespace):
    index = _load_search_index(args.index)
    tenant_id = None if args.unsafe_global else args.tenant
    hits = index.search(args.question, tenant_id=tenant_id, top_k=args.top_k)
    event = build_retrieval_event(
        tenant_id=args.tenant,
        question=args.question,
        hits=hits,
        top_k=args.top_k,
        unsafe_global_search=args.unsafe_global,
    )
    write_event(args.log, event.pop("event_type"), event)
    return hits


def command_query(args: argparse.Namespace) -> None:
    hits = _search(args)
    print(json.dumps([hit.to_dict() for hit in hits], ensure_ascii=False, indent=2))


def command_ask(args: argparse.Namespace) -> None:
    hits = _search(args)
    if not hits:
        raise SystemExit("No relevant document chunks found.")
    messages = build_baseline_messages(args.question, hits)
    if args.show_prompt:
        print(json.dumps(messages, ensure_ascii=False, indent=2))
        return
    answer = chat(endpoint=args.endpoint, model=args.model, messages=messages)
    event = build_model_response_event(
        tenant_id=args.tenant,
        model=args.model,
        answer=answer,
    )
    write_event(args.log, event.pop("event_type"), event)
    print(answer)


def command_evaluate(args: argparse.Namespace) -> None:
    index = _load_search_index(args.index)
    report = evaluate(index, args.dataset, args.top_k)
    print(json.dumps(report, ensure_ascii=False, indent=2))


def command_emit_test_event(args: argparse.Namespace) -> None:
    event = build_test_event(args.kind)
    event_type = event.pop("event_type")
    write_event(args.log, event_type, event)
    print(
        json.dumps(
            {"status": "ok", "kind": args.kind, "log": str(args.log)},
            ensure_ascii=False,
            indent=2,
        )
    )


def add_search_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--tenant", required=True, help="Tenant allowed to retrieve documents.")
    parser.add_argument("--question", required=True, help="User question.")
    parser.add_argument("--top-k", type=int, default=3)
    parser.add_argument("--unsafe-global", action="store_true", help="Disable tenant filtering for a lab demo.")
    parser.add_argument("--index", type=Path, default=DEFAULT_INDEX)
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="RAG poisoning security lab")
    subparsers = parser.add_subparsers(dest="command", required=True)

    ingest_parser = subparsers.add_parser("ingest", help="Build the local corpus index.")
    ingest_parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    ingest_parser.add_argument("--quarantine", type=Path, default=DEFAULT_QUARANTINE)
    ingest_parser.add_argument("--index", type=Path, default=DEFAULT_INDEX)
    ingest_parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    ingest_parser.add_argument(
        "--policy",
        choices=["off", "audit", "enforce"],
        default="audit",
        help="off=allow, audit=alert without moving, enforce=quarantine before indexing.",
    )
    ingest_parser.set_defaults(handler=command_ingest)

    query_parser = subparsers.add_parser("query", help="Retrieve chunks without calling an LLM.")
    add_search_arguments(query_parser)
    query_parser.set_defaults(handler=command_query)

    ask_parser = subparsers.add_parser("ask", help="Retrieve chunks and call a local Ollama model.")
    add_search_arguments(ask_parser)
    ask_parser.add_argument("--endpoint", default="http://127.0.0.1:11434")
    ask_parser.add_argument("--model", default="qwen2.5:0.5b")
    ask_parser.add_argument("--show-prompt", action="store_true")
    ask_parser.set_defaults(handler=command_ask)

    evaluate_parser = subparsers.add_parser("evaluate", help="Measure retrieval-stage security metrics.")
    evaluate_parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    evaluate_parser.add_argument("--index", type=Path, default=DEFAULT_INDEX)
    evaluate_parser.add_argument("--top-k", type=int, default=2)
    evaluate_parser.set_defaults(handler=command_evaluate)

    test_event_parser = subparsers.add_parser(
        "emit-test-event", help="Append a Wazuh smoke-test event to the audit log."
    )
    test_event_parser.add_argument(
        "--kind",
        choices=["poisoned-retrieval", "canary-leak", "cross-tenant"],
        required=True,
    )
    test_event_parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    test_event_parser.set_defaults(handler=command_emit_test_event)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.handler(args)
