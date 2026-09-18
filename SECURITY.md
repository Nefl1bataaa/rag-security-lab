# Security Policy

This repository is an isolated security lab. It contains synthetic tenants, documents, events, hashes and the non-secret canary `CANARY-RAG-2026`.

## Safe use

- Run only in systems you own or are explicitly authorized to test.
- Do not ingest real credentials, API keys, personal data or internal documents.
- Keep Ollama bound to the loopback interface unless an authenticated network design is in place.
- Treat `--unsafe-global` as an intentionally vulnerable lab option.
- Review dry-run findings before enabling document quarantine in a new corpus.

## Reporting issues

Do not include real secrets or personal data in an issue. For a suspected vulnerability, provide a minimal synthetic reproduction and clearly identify the affected component and version.
