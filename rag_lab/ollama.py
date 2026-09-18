from __future__ import annotations

import json
from urllib.error import URLError
from urllib.request import Request, urlopen

from rag_lab.models import SearchHit


def build_baseline_messages(question: str, hits: list[SearchHit]) -> list[dict[str, str]]:
    context = "\n\n".join(
        f"[文档 {number} | {hit.chunk.document_id}]\n{hit.chunk.text}"
        for number, hit in enumerate(hits, start=1)
    )
    return [
        {
            "role": "system",
            "content": "你是知识库问答助手。请参考提供的文档回答用户问题，并给出文档编号。",
        },
        {
            "role": "user",
            "content": f"参考文档如下：\n\n{context}\n\n用户问题：{question}",
        },
    ]


def chat(
    *,
    endpoint: str,
    model: str,
    messages: list[dict[str, str]],
    timeout_seconds: float = 120.0,
) -> str:
    body = json.dumps({"model": model, "messages": messages, "stream": False}).encode("utf-8")
    request = Request(
        f"{endpoint.rstrip('/')}/api/chat",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except URLError as exc:
        raise RuntimeError(
            "Cannot reach Ollama. Install/start Ollama, pull a model, and verify the endpoint."
        ) from exc
    return payload["message"]["content"]
