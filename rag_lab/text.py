from __future__ import annotations

import re


TOKEN_PATTERN = re.compile(r"[a-zA-Z0-9_]+|[\u4e00-\u9fff]")


def tokenize(text: str) -> list[str]:
    """Tokenize mixed Chinese/English text without external dependencies."""
    raw = TOKEN_PATTERN.findall(text.lower())
    chinese = [token for token in raw if len(token) == 1 and "\u4e00" <= token <= "\u9fff"]
    bigrams = [f"{left}{right}" for left, right in zip(chinese, chinese[1:])]
    return raw + bigrams


def split_text(text: str, max_chars: int = 520) -> list[str]:
    """Split text by paragraphs while keeping chunks small enough for a RAG context."""
    paragraphs = [part.strip() for part in re.split(r"\n\s*\n", text) if part.strip()]
    chunks: list[str] = []
    current = ""

    for paragraph in paragraphs:
        if len(paragraph) > max_chars:
            if current:
                chunks.append(current)
                current = ""
            for start in range(0, len(paragraph), max_chars):
                chunks.append(paragraph[start : start + max_chars])
            continue

        candidate = f"{current}\n\n{paragraph}".strip()
        if current and len(candidate) > max_chars:
            chunks.append(current)
            current = paragraph
        else:
            current = candidate

    if current:
        chunks.append(current)
    return chunks
