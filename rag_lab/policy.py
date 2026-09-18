from __future__ import annotations

import hashlib
import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from rag_lab.audit import write_event


PolicyMode = Literal["off", "audit", "enforce"]
SUPPORTED_SUFFIXES = {".txt", ".md"}

SIGNATURES = {
    "canary_token": re.compile(r"CANARY-RAG-2026", re.I),
    "ignore_instructions": re.compile(
        r"ignore\s+(?:all\s+)?(?:previous\s+)?instructions", re.I
    ),
    "system_override": re.compile(r"system\s+override|prompt\s+injection", re.I),
    "chinese_ignore_instruction": re.compile(r"忽略.{0,20}(?:指令|规则|要求)"),
    "forced_output": re.compile(r"(?:最终答案|回答).{0,30}(?:必须|原样).{0,20}输出"),
    "lab_debug_instruction": re.compile(r"实验调试指令"),
}


@dataclass(frozen=True)
class PolicyFinding:
    document_id: str
    tenant_id: str
    source_path: Path
    document_sha256: str
    signatures: tuple[str, ...]


@dataclass(frozen=True)
class PolicyResult:
    mode: PolicyMode
    suspicious_document_count: int
    quarantined_document_count: int
    findings: tuple[PolicyFinding, ...]
    quarantine_paths: tuple[Path, ...]


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def scan_corpus(corpus_dir: Path) -> list[PolicyFinding]:
    findings: list[PolicyFinding] = []
    for source in sorted(corpus_dir.rglob("*")):
        if not source.is_file() or source.suffix.lower() not in SUPPORTED_SUFFIXES:
            continue
        relative = source.relative_to(corpus_dir)
        if len(relative.parts) < 3:
            continue
        text = source.read_text(encoding="utf-8", errors="replace")
        signatures = tuple(
            name for name, pattern in SIGNATURES.items() if pattern.search(text)
        )
        if not signatures:
            continue
        findings.append(
            PolicyFinding(
                document_id=relative.as_posix(),
                tenant_id=relative.parts[0],
                source_path=source,
                document_sha256=file_sha256(source),
                signatures=signatures,
            )
        )
    return findings


def _quarantine_destination(
    finding: PolicyFinding, corpus_dir: Path, quarantine_dir: Path
) -> Path:
    relative = finding.source_path.relative_to(corpus_dir)
    destination = quarantine_dir / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        destination = destination.with_name(
            f"{destination.stem}-{stamp}{destination.suffix}"
        )
    return destination


def _event_details(finding: PolicyFinding, mode: PolicyMode) -> dict[str, object]:
    if mode == "enforce":
        action, disposition = "quarantined", "blocked"
    elif mode == "audit":
        action, disposition = "alert", "observed"
    else:
        action, disposition = "allowed", "vulnerable-baseline"
    return {
        "schema_version": 1,
        "lab_component": "rag-security-lab",
        "data_classification": "synthetic",
        "tenant_id": finding.tenant_id,
        "document_id": finding.document_id,
        "document_sha256": finding.document_sha256,
        "suspicious_patterns": list(finding.signatures),
        "suspicious_document": True,
        "policy_mode": mode,
        "risk_score": 90,
        "action": action,
        "environment": "isolated",
        "application": "rag-security-lab",
        "disposition": disposition,
    }


def apply_ingestion_policy(
    *,
    corpus_dir: Path,
    quarantine_dir: Path,
    audit_log: Path,
    mode: PolicyMode,
) -> PolicyResult:
    findings = scan_corpus(corpus_dir)
    quarantine_paths: list[Path] = []

    for finding in findings:
        if mode == "enforce":
            destination = _quarantine_destination(finding, corpus_dir, quarantine_dir)
            shutil.move(str(finding.source_path), str(destination))
            quarantine_paths.append(destination)
            event_type = "rag_integrity"
        else:
            event_type = "rag_ingestion_policy"
        write_event(audit_log, event_type, _event_details(finding, mode))

    return PolicyResult(
        mode=mode,
        suspicious_document_count=len(findings),
        quarantined_document_count=len(quarantine_paths),
        findings=tuple(findings),
        quarantine_paths=tuple(quarantine_paths),
    )
