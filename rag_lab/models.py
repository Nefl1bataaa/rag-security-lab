from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class Chunk:
    chunk_id: str
    document_id: str
    tenant_id: str
    source_path: str
    trust_level: str
    is_poisoned: bool
    text: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Chunk":
        return cls(**value)


@dataclass(frozen=True)
class SearchHit:
    chunk: Chunk
    score: float

    def to_dict(self) -> dict[str, Any]:
        return {"score": round(self.score, 6), **self.chunk.to_dict()}
