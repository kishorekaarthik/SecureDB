# SecureDB Vault

A multi-tenant **PII vault and tokenization service** for Indian companies handling PAN,
Aadhaar and bank details under the DPDP Act 2023. Applications store opaque tokens; real
values live encrypted in the vault and are revealed (in full or masked) only to API keys whose
policy allows it. Every access lands in a tamper-evident audit log.

> **Status:** Milestone 2 of 7 (crypto). See the
> [design spec](docs/superpowers/specs/2026-09-28-securedb-vault-design.md).

## Local setup (Windows, no Docker)

Prerequisites: [uv](https://docs.astral.sh/uv/), PostgreSQL 17 with `psql` on PATH, Git, and
Python 3.13 (if Windows Smart App Control is on, install the signed build with
`py install 3.13`; the project prefers an installed Python over uv-managed builds).

```powershell
uv sync
uv run python scripts/make_dev_env.py        # writes .env and .env.test with random passwords
powershell -ExecutionPolicy Bypass -File scripts/bootstrap_db.ps1   # asks for the postgres password
uv run alembic upgrade head
uv run securedb init                          # master key -> Windows Credential Manager
uv run securedb serve                         # http://127.0.0.1:8000/docs
```

## How values are protected

- A random 256-bit **master key** lives in the OS keychain (or in a file encrypted with an
  Argon2id-derived key). It never touches the database.
- Each tenant gets its own **data key** and **lookup key**, stored only wrapped (AES-256-GCM)
  by the master key, in a table guarded by forced PostgreSQL row-level security.
- Every value is encrypted with AES-256-GCM, with its tenant, token, type and key version bound
  in as associated data, so a ciphertext moved to another tenant or token fails to decrypt.
- If the master key cannot be unlocked the API still starts, but `/readyz` reports
  `key_provider: false`.

## Development

```powershell
uv run pytest                  # needs the securedb_test database from the bootstrap step
uv run ruff check . ; uv run ruff format --check . ; uv run mypy
uv run python -m bandit -q -r src ; uv run python -m pip_audit --skip-editable
```

## License

MIT (license file added in a later milestone).
