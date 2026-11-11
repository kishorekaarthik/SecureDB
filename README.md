# SecureDB Vault

A multi-tenant **PII vault and tokenization service** for companies that handle PAN, Aadhaar
and bank details under India's DPDP Act 2023.

Your application sends a sensitive value and gets back an opaque token such as
`tok_pan_8fK2…`. Your own database stores only tokens. When a service needs the real value it
asks the vault, which returns it in full, masked (`XXXXXX234F`) or not at all, depending on
that API key's policy. Every access is recorded in a tamper-evident audit log.

## What it does

- **Tokenization API** for PAN, Aadhaar (Verhoeff-checked), bank account + IFSC, phone, e-mail
  and generic values. The same value always maps to the same token within a tenant.
- **Envelope encryption**: AES-256-GCM with a data key per tenant, wrapped by a master key held
  in the OS keychain, a passphrase-protected file, or AWS KMS. Each ciphertext is bound to its
  tenant, token, type and key version.
- **Tenant isolation in the database**: forced PostgreSQL row-level security on every tenant
  table, plus a least-privilege application role.
- **Policies per API key**: allow, mask or deny for each field type; deny by default; scoped,
  revocable keys; rate limiting.
- **Tamper-evident audit log**: a per-tenant hash chain written in the same transaction as each
  operation, with verification against an external anchor.
- **DPDP data-subject rights**: erasure and export per subject, including values shared by
  several people.
- **Key rotation**: data-key rotation with resumable re-encryption beside live traffic, and
  crash-safe master-key rotation.
- **Admin console**: password + TOTP sign-in, owner and viewer roles, and no JavaScript.

## Architecture

```
            ┌──────────── tenant applications ────────────┐      ┌── admins ──┐
            │  POST /v1/tokens   POST /v1/tokens/detokenize│      │  /console  │
            └───────────────────────┬─────────────────────┘      └─────┬──────┘
                                    ▼                                  ▼
        ┌──────────────────────── FastAPI app ────────────────────────────┐
        │ api (auth, scopes, rate limit)        console (sessions, CSRF)  │
        │ vault (validate, tokenize, erase)     policy (allow/mask/deny)  │
        │ audit (hash chain)                    crypto (AEAD, key ring)   │
        └───────────────┬───────────────────────────────┬─────────────────┘
                        ▼                               ▼
          PostgreSQL (row-level security)      Key provider (master key)
          ciphertext, wrapped keys, audit      OS keychain | file | AWS KMS
```

More detail: [threat model](docs/threat-model.md) · [cryptographic design](docs/crypto-design.md)
· [decision records](docs/adr/README.md) · [design spec](docs/superpowers/specs/2026-09-28-securedb-vault-design.md)

## Quick start (Windows, no Docker)

Prerequisites: [uv](https://docs.astral.sh/uv/), PostgreSQL 17 with `psql` on PATH, Git, and
Python 3.13 (if Windows Smart App Control is on, install the signed build with
`py install 3.13`).

```powershell
uv sync
uv run python scripts/make_dev_env.py        # writes .env and .env.test with random passwords
powershell -ExecutionPolicy Bypass -File scripts/bootstrap_db.ps1   # asks for the postgres password
uv run alembic upgrade head
uv run securedb init                          # master key -> OS keychain
uv run securedb seed-demo                     # two demo tenants, API keys, console users
uv run securedb serve                         # http://127.0.0.1:8000
```

`seed-demo` prints two API keys per tenant, a sample token, and the console sign-in details.
Add the printed `otpauth://` link to an authenticator app to sign in at
`http://127.0.0.1:8000/console`. The API reference is at `/docs` in the dev environment.

## Try the API

```bash
# Tokenize (backend key)
curl -s http://127.0.0.1:8000/v1/tokens \
  -H "Authorization: Bearer $BACKEND_KEY" -H "Content-Type: application/json" \
  -d '{"items":[{"type":"pan","value":"ABCDE1234F","subject_id":"cust-42"}]}'

# Detokenize: the backend key gets the value, the support key gets it masked
curl -s http://127.0.0.1:8000/v1/tokens/detokenize \
  -H "Authorization: Bearer $SUPPORT_KEY" -H "Content-Type: application/json" \
  -d '{"tokens":["tok_pan_..."]}'
```

| Endpoint | Scope | Purpose |
|---|---|---|
| `POST /v1/tokens` | `tokenize` | Tokenize up to 100 values |
| `POST /v1/tokens/detokenize` | `detokenize` | Full, masked or `not_available` per token |
| `DELETE /v1/tokens/{token}` | `subjects:erase` | Delete one token |
| `DELETE /v1/subjects/{id}` | `subjects:erase` | Erase a data subject |
| `GET /v1/subjects/{id}/export` | `subjects:export` | Tokens, values by policy, access history |
| `GET /v1/audit`, `GET /v1/audit/verify` | `audit:read` | Read and verify the audit chain |
| `GET /healthz`, `GET /readyz` | none | Liveness; database and key-provider readiness |

## Operator commands

```
securedb init | serve | seed-demo
securedb create-tenant NAME
securedb create-api-key --tenant T --name N --scope tokenize --scope detokenize
securedb set-policy --tenant T --key PREFIX --type pan --action detokenize --effect mask
securedb revoke-api-key --tenant T PREFIX
securedb create-user --tenant T --email E --role owner|viewer      securedb unlock-user ...
securedb rotate-dek --tenant T        securedb reencrypt --tenant T        securedb rotate-master
securedb verify-audit --tenant T [--anchor-seq N --anchor-hash H]
```

## Development

```powershell
uv run python -m pytest        # needs the securedb_test database from the bootstrap step
uv run python -m ruff check . ; uv run python -m ruff format --check . ; uv run python -m mypy
uv run python -m bandit -q -r src ; uv run python -m pip_audit --skip-editable
```

The suite runs against a real PostgreSQL database so that row-level security, grants and
concurrency are tested for real. It includes property-based tests, multi-threaded race tests
and security-regression tests (cross-tenant access, tampering, CSRF, log redaction).

## Limits

This is a portfolio project, not an audited product. Rate limits and key caches are per
process; an attacker with control of the running process or the master key is out of scope;
the KMS provider is tested against a fake client. See the [threat model](docs/threat-model.md).

The original Flask application this project grew out of is kept on the `legacy-flask` branch.

## License

[MIT](LICENSE)
