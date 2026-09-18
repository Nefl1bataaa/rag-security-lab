from __future__ import annotations

import hashlib
import json
from pathlib import Path

from rag_lab.models import Chunk
from rag_lab.text import split_text


SUPPORTED_SUFFIXES = {".txt", ".md"}


def _chunk_id(document_id: str, number: int, text: str) -> str:
    digest = hashlib.sha256(f"{document_id}:{number}:{text}".encode("utf-8")).hexdigest()
    return digest[:16]


def load_corpus(corpus_dir: Path) -> list[Chunk]:
    """Load data/corpus/<tenant>/<benign|poisoned>/*.txt into labeled chunks."""
    chunks: list[Chunk] = []
    for path in sorted(corpus_dir.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SUPPORTED_SUFFIXES:
            continue

        relative = path.relative_to(corpus_dir)
        if len(relative.parts) < 3:
            raise ValueError(
                f"Invalid corpus path {relative}; expected <tenant>/<benign|poisoned>/<file>."
            )

        tenant_id, classification = relative.parts[0], relative.parts[1]
        if classification not in {"benign", "poisoned"}:
            raise ValueError(f"Unknown classification {classification!r} in {relative}.")

        document_id = relative.as_posix()
        text = path.read_text(encoding="utf-8")
        for number, content in enumerate(split_text(text)):
            chunks.append(
                Chunk(
                    chunk_id=_chunk_id(document_id, number, content),
                    document_id=document_id,
                    tenant_id=tenant_id,
                    source_path=str(path.resolve()),
                    trust_level="untrusted" if classification == "poisoned" else "internal",
                    is_poisoned=classification == "poisoned",
                    text=content,
                )
            )
    return chunks


def save_index(chunks: list[Chunk], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "chunk_count": len(chunks),
        "chunks": [chunk.to_dict() for chunk in chunks],
    }
    output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def load_index(index_path: Path) -> list[Chunk]:
    payload = json.loads(index_path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1:
        raise ValueError("Unsupported index schema version.")
    return [Chunk.from_dict(value) for value in payload["chunks"]]
