from __future__ import annotations

import math
from collections import Counter

from rag_lab.models import Chunk, SearchHit
from rag_lab.text import tokenize


class TfidfIndex:
    """Small, inspectable TF-IDF baseline suitable for a security lab."""

    def __init__(self, chunks: list[Chunk]) -> None:
        if not chunks:
            raise ValueError("Cannot create an index without chunks.")
        self.chunks = chunks
        self._token_counts = [Counter(tokenize(chunk.text)) for chunk in chunks]
        document_frequency: Counter[str] = Counter()
        for counts in self._token_counts:
            document_frequency.update(counts.keys())
        total = len(chunks)
        self._idf = {
            token: math.log((1 + total) / (1 + frequency)) + 1.0
            for token, frequency in document_frequency.items()
        }
        self._vectors = [self._vectorize_counts(counts) for counts in self._token_counts]

    def _vectorize_counts(self, counts: Counter[str]) -> dict[str, float]:
        weighted = {
            token: (1.0 + math.log(count)) * self._idf.get(token, 0.0)
            for token, count in counts.items()
        }
        norm = math.sqrt(sum(value * value for value in weighted.values())) or 1.0
        return {token: value / norm for token, value in weighted.items()}

    def _query_vector(self, query: str) -> dict[str, float]:
        counts = Counter(tokenize(query))
        return self._vectorize_counts(counts)

    @staticmethod
    def _similarity(left: dict[str, float], right: dict[str, float]) -> float:
        if len(left) > len(right):
            left, right = right, left
        return sum(value * right.get(token, 0.0) for token, value in left.items())

    def search(
        self,
        query: str,
        *,
        tenant_id: str | None,
        top_k: int = 3,
    ) -> list[SearchHit]:
        if top_k < 1:
            raise ValueError("top_k must be at least 1.")
        query_vector = self._query_vector(query)
        hits = []
        for chunk, vector in zip(self.chunks, self._vectors):
            if tenant_id is not None and chunk.tenant_id != tenant_id:
                continue
            score = self._similarity(query_vector, vector)
            if score > 0:
                hits.append(SearchHit(chunk=chunk, score=score))
        hits.sort(key=lambda hit: (-hit.score, hit.chunk.chunk_id))
        return hits[:top_k]
