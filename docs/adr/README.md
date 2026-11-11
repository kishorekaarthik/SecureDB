# Architecture decision records

Each record states one decision, why it was made, and what it costs.

| # | Decision |
|---|---|
| [0001](0001-fastapi-postgres-modular-monolith.md) | FastAPI + PostgreSQL as a modular monolith |
| [0002](0002-envelope-encryption-pluggable-key-provider.md) | Envelope encryption with a pluggable key provider |
| [0003](0003-api-key-hashing.md) | SHA-256, not Argon2id, for API key secrets |
| [0004](0004-random-tokens-hmac-lookup-token-subjects.md) | Random tokens, HMAC lookup, and a token–subject link table |
| [0005](0005-hash-chained-audit-log.md) | Hash-chained audit log with external anchors |
| [0006](0006-console-without-javascript.md) | Admin console without JavaScript |
