# SecureDB Vault — Design Spec

- **Date:** 2026-09-28
- **Status:** Approved in conversation; pending written-spec review
- **Purpose:** Portfolio/resume project. Optimise for demonstrable engineering judgment (threat model, correct crypto, clean architecture, tests, CI, demo), not paying-customer features.
- **Predecessor:** `kishorekaarthik/SecureDB` (Flask + MongoDB personal vault). This is a from-scratch rebuild pivoted to a B2B PII vault; little code is reused.

---

## 1. Problem and scope

### 1.1 Problem

Indian companies (fintech, lending, HR, e-commerce) collect customer PII such as PAN, Aadhaar and bank details. The Digital Personal Data Protection (DPDP) Act 2023 and RBI data-localisation rules push them to keep that data encrypted and isolated, expose it to internal systems only when necessary, audit every access, and honour erasure requests.

### 1.2 Product

SecureDB Vault is a **multi-tenant PII vault / tokenization service**. A tenant (company) sends sensitive values to the API and receives opaque tokens (e.g. `tok_pan_8f3k…`). The tenant's own database stores only tokens. When a service needs the real value it calls detokenize and receives it in full or masked (e.g. `XXXXXX1234F`), according to that API key's policy. Every access is written to a tamper-evident audit log.

### 1.3 Supported field types

| Type | Validation / normalisation | Default mask |
|---|---|---|
| `pan` | `^[A-Z]{5}[0-9]{4}[A-Z]$` after uppercasing and stripping whitespace | `XXXXXX` + last 4 characters (`XXXXXX234F`) |
| `aadhaar` | 12 digits, first digit 2–9, valid Verhoeff checksum; spaces/hyphens stripped | `XXXX XXXX ` + last 4 |
| `bank_account` | Object `{account_number, ifsc}`; account number 9–18 digits; IFSC `^[A-Z]{4}0[A-Z0-9]{6}$` | Account: `X…` + last 4; IFSC shown in full |
| `phone` | E.164 after normalisation (Indian 10-digit numbers get `+91`) | Country code + `XXXXXX` + last 4 |
| `email` | Syntactic validation; lowercased | First character + `***@` + domain |
| `generic` | Any UTF-8 string up to 4 KiB | `****` |

### 1.4 Tokens

- Tokens are **random** (`tok_<type>_` + 22 characters of base62 from `secrets`), never derived from the value.
- A per-tenant **lookup HMAC** (HMAC-SHA256 of type + normalised value under a tenant-derived key) enables deduplication: tokenizing the same value twice in the same tenant returns the same token. It also allows exact-match lookup; no other search is supported.

### 1.5 In scope

Tenants, API keys and scoped policies; envelope encryption with per-tenant data keys and rotation; hash-chained audit log with verification; DPDP subject erasure and export; admin console; operator CLI; tests and CI; documentation.

### 1.6 Out of scope (YAGNI)

Billing, SSO, format-preserving encryption, multi-region deployment, file/document storage, tiered rate limits, horizontal scaling (in-process rate limiting is acceptable and documented), Docker for local development.

### 1.7 Threat model

| Threat | Mitigation |
|---|---|
| Database dump stolen | Values are AES-256-GCM ciphertext. Data keys are wrapped by a master key that is never stored in the database. |
| Application server compromised (at rest) | Master key exists only in process memory after unlock. Detokenization is policy-gated and audited. |
| API key leaked | Keys stored as argon2id hashes, scoped, revocable, with `last_used_at` for detection. |
| Cross-tenant access | Postgres row-level security on every tenant-owned table, plus tenant-bound data keys, plus `tenant_id` in the AEAD associated data, so ciphertext moved between tenants fails to decrypt. |
| Insider edits or deletes audit rows | Per-tenant hash chain; the application DB role has INSERT/SELECT only on `audit_log`; `verify` detects edits and deletions. |
| Token enumeration | Denied and non-existent tokens return an identical per-token error. |
| Console attacks | Server-side sessions, CSRF tokens, TOTP second factor, `HttpOnly`/`Secure`/`SameSite=Strict` cookies, strict CSP with no third-party scripts. |
| Secrets in logs | Structured logging with a redaction filter, covered by tests. |

**Explicitly not defended:** an attacker with control of the live process's memory, or a malicious operator who holds the master passphrase. Documented openly in `docs/threat-model.md`.

---

## 2. Architecture

### 2.1 Style

A **modular monolith**: one FastAPI application, one PostgreSQL database, one process. Modules communicate only through their public interfaces, so any module could later be extracted into a service.

### 2.2 Stack

- Python 3.13 (pinned; managed with `uv`, lockfile `uv.lock`)
- FastAPI, Pydantic v2, pydantic-settings
- PostgreSQL 17 (native install locally; service container in CI)
- SQLAlchemy 2.x (sync, psycopg 3), Alembic
- `cryptography` (AES-GCM, HKDF, HMAC), `argon2-cffi`, `keyring`, `pyotp`
- Jinja2 + HTMX (vendored, served locally) for the console
- Typer for the CLI, structlog for logging
- boto3 for the optional KMS adapter; `moto` in tests
- No Docker, no Node.

Sync SQLAlchemy is chosen deliberately: the workload is CPU-bound crypto plus short queries, and sync code keeps transactions and RLS context simpler to reason about. FastAPI runs sync routes in its threadpool.

### 2.3 Module layout (`src/securedb/`)

| Module | Responsibility | Depends on |
|---|---|---|
| `config` | Settings from env / `.env`; refuses to start with invalid config | — |
| `db` | Engine, session factory, `tenant_session(tenant_id)` that sets `app.tenant_id` for RLS; SQLAlchemy models; Alembic migrations | config |
| `crypto` | `KeyProvider` protocol, `LocalKeyProvider`, `AwsKmsKeyProvider`; `KeyRing` (DEK load/unwrap/cache per tenant+version); AEAD encrypt/decrypt; lookup-HMAC key derivation | config |
| `tenants` | Tenants, API keys (issue, hash, verify, revoke), console users | db, crypto |
| `policy` | `PolicyEngine.decide(api_key, field_type, action) → ALLOW | MASK | DENY` (deny by default) | db |
| `vault` | `TokenService`: tokenize, detokenize, delete, erase subject, export subject; field validators and maskers | crypto, policy, audit, db |
| `audit` | `AuditLog.append(...)` inside the caller's transaction; `verify(tenant_id)` | db |
| `api` | `/v1` HTTP routes, API-key auth dependency, error handlers, rate limiter | services only |
| `console` | Server-rendered admin UI, session auth, CSRF, TOTP | services only |
| `cli` | Operator commands | services |

`api` and `console` never touch models or crypto directly.

### 2.4 Key hierarchy

```
Master key  (held by a KeyProvider; unlocked at startup; memory only)
  └─ wraps → Tenant DEK (256-bit, random), stored wrapped in tenant_keys, versioned
        ├─ encrypts → token values with AES-256-GCM
        │              nonce: 96-bit random per encryption
        │              AAD:   tenant_id | token | type | key_version

Master key
  └─ wraps → Tenant lookup key (256-bit, random), stored wrapped in tenants.wrapped_lookup_key
        └─ HMAC-SHA256(type | normalised value) → lookup_hmac
```

- **LocalKeyProvider:** on `securedb init` a random 256-bit master key is generated. It is either (a) stored in the OS keychain via `keyring`, or (b) wrapped with a key derived from an operator passphrase using Argon2id (parameters stored alongside) and written to a key file outside the repo. Wrapping/unwrapping DEKs uses AES-256-GCM with the master key.
- **AwsKmsKeyProvider:** DEK wrap/unwrap via KMS `Encrypt`/`Decrypt` with an encryption context of `{tenant_id, key_version}`. Disabled unless configured.
- The lookup key is separate from the DEKs and is not rotated by DEK rotation, because rotating it would invalidate deduplication (it is re-wrapped on master rotation like the DEKs). This trade-off is recorded in an ADR.

### 2.5 Rotation

- **DEK rotation** (per tenant): create version N+1 with status `active`; the previous version becomes `retiring`. New writes use N+1. `securedb reencrypt --tenant X` re-encrypts rows in batches (each batch a transaction, audited), then marks old versions `retired`. Retired versions are kept until no row references them.
- `reencrypt` also re-encrypts console users' `totp_secret_enc`, which is encrypted with the tenant DEK.
- **Master key rotation:** `securedb rotate-master` unwraps every DEK and lookup key with the old master key and re-wraps it with the new one, in one transaction. Token rows are untouched.

### 2.6 Flows

**Tokenize** — `POST /v1/tokens`
1. Authenticate the API key; open a tenant session (RLS active).
2. For each item: policy check (`tokenize`, type); validate and normalise; compute lookup HMAC.
3. If `(tenant, type, lookup_hmac)` exists, return the existing token; otherwise encrypt and insert.
4. Append one audit entry for the request in the same transaction.

**Detokenize** — `POST /v1/tokens/detokenize` (POST so tokens never appear in URLs or access logs)
1. Authenticate; open tenant session.
2. For each token: load the row; policy check (`detokenize`, type) → ALLOW / MASK / DENY; decrypt; mask if required.
3. Denied and missing tokens both return `{"token": …, "error": "not_available"}`.
4. Append one audit entry listing every token and its outcome.

**Erase subject** — `DELETE /v1/subjects/{subject_id}`: hard-delete all token rows for the subject in the tenant; audit the erasure with token IDs and count only. The audit log never contains values, so erasure never breaks the chain.

**Export subject** — `GET /v1/subjects/{subject_id}/export`: token IDs, types, created timestamps and access history from the audit log. Values are returned only if the calling key's policy allows detokenize for that type (masked or full accordingly).

### 2.7 Audit chain

- One chain per tenant. Each entry has `seq` (monotonic per tenant), `ts`, `actor`, `action`, `token_ids`, `outcome`, `request_id`, `prev_hash`, `hash`.
- `hash = SHA256(prev_hash || canonical_json(entry_without_hash))`; the first entry uses 32 zero bytes as `prev_hash`.
- Appends take a per-tenant advisory lock so `seq` and `prev_hash` are assigned without races.
- The application DB role has only `INSERT` and `SELECT` on `audit_log`. Migrations run as a separate owner role.
- `GET /v1/audit/verify` recomputes the chain and returns either `ok` with the entry count, or the first broken `seq`.

---

## 3. Data model

All tenant-owned tables carry `tenant_id` and an RLS policy `USING (tenant_id = current_setting('app.tenant_id')::uuid)`. RLS is `FORCE`d so it also applies to the table owner.

| Table | Columns |
|---|---|
| `tenants` | `id` uuid PK, `name`, `wrapped_lookup_key` bytea, `created_at` |
| `tenant_keys` | `tenant_id`, `version` int, `wrapped_dek` bytea, `provider` text, `provider_key_id` text, `status` (`active`/`retiring`/`retired`), `created_at`; PK `(tenant_id, version)`; at most one `active` per tenant (partial unique index) |
| `api_keys` | `id` uuid PK, `tenant_id`, `prefix` (unique), `secret_hash` (argon2id), `name`, `scopes` text[], `created_at`, `revoked_at`, `last_used_at` |
| `policies` | `id`, `tenant_id`, `api_key_id`, `field_type`, `action` (`tokenize`/`detokenize`), `effect` (`allow`/`mask`); unique `(api_key_id, field_type, action)` |
| `tokens` | `token` text PK, `tenant_id`, `type`, `subject_id` text null, `lookup_hmac` bytea, `ciphertext` bytea, `nonce` bytea, `key_version` int, `created_at`; unique `(tenant_id, type, lookup_hmac)`; index `(tenant_id, subject_id)` |
| `audit_log` | `tenant_id`, `seq` bigint, `ts`, `actor_type` (`api_key`/`console_user`/`system`), `actor_id`, `action`, `token_ids` text[], `outcome` jsonb, `request_id`, `prev_hash` bytea, `hash` bytea; PK `(tenant_id, seq)` |
| `console_users` | `id`, `tenant_id`, `email` (unique per tenant), `password_hash` (argon2id), `totp_secret_enc` bytea (encrypted with the tenant DEK), `role` (`owner`/`viewer`), `created_at`, `failed_logins`, `locked_until` |
| `console_sessions` | `id` (random 256-bit, stored hashed), `user_id`, `tenant_id`, `csrf_token`, `created_at`, `expires_at` |

API-key scopes: `tokenize`, `detokenize`, `subjects:erase`, `subjects:export`, `audit:read`. Scopes gate endpoints; policies gate field types within `tokenize`/`detokenize`. Absence of a matching policy means DENY.

---

## 4. Interfaces

### 4.1 HTTP API (`/v1`, OpenAPI at `/docs`)

- Auth header: `Authorization: Bearer sdb_live_<prefix>_<secret>`. Lookup by prefix, then argon2id verification of the secret.
- `POST /v1/tokens` — body `{items: [{type, value, subject_id?}]}` (1–100 items) → `{items: [{token, type, created: bool}]}`
- `POST /v1/tokens/detokenize` — body `{tokens: [...]}` (1–100) → `{items: [{token, value?, masked: bool, error?}]}`
- `DELETE /v1/tokens/{token}` → 204
- `DELETE /v1/subjects/{subject_id}` → `{deleted: n}`
- `GET /v1/subjects/{subject_id}/export`
- `GET /v1/audit?from=&to=&action=&cursor=` (cursor pagination by `seq`)
- `GET /v1/audit/verify`
- `GET /healthz` (process alive), `GET /readyz` (DB reachable and key provider unlocked)
- Errors: RFC 7807 `application/problem+json` with `type`, `title`, `status`, `detail`, `request_id`.
- Rate limit: per API key, fixed window, in-process; `429` with `Retry-After`.

### 4.2 Console (`/console`)

- Login: email + password, then TOTP. Five failures lock the account for 15 minutes.
- Sessions stored server-side; cookie holds only the random session ID. Session lifetime 8 hours, idle timeout 30 minutes.
- Every state-changing request is POST with a CSRF token checked server-side.
- Security headers: CSP `default-src 'self'` (no inline scripts), `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, HSTS when served over HTTPS.
- Pages: Overview (token counts by type, recent activity, active key version); API keys (create — secret shown once — edit scopes/policies, revoke); Audit log (filter, paginate, "Verify chain"); Keys (rotate DEK, re-encryption progress); Playground (tokenize/detokenize using a selected key to demonstrate masking).
- Roles: `owner` can change keys, policies and rotation; `viewer` is read-only.

### 4.3 CLI (`securedb`)

`init` · `serve` · `create-tenant` · `create-user` · `rotate-dek --tenant` · `reencrypt --tenant` · `rotate-master` · `seed-demo` (two tenants with sample data and keys with different policies) · `verify-audit --tenant`.

---

## 5. Error handling and logging

- A small hierarchy of domain exceptions (`ValidationError`, `PolicyDenied`, `NotFound`, `Unauthorized`, `KeyProviderLocked`, `CryptoError`) mapped to problem+json responses in one handler module.
- `CryptoError` returns a generic 500; details go only to logs.
- structlog JSON logs with `request_id` bound per request. A redaction processor removes known sensitive keys (`value`, `secret`, `password`, `totp`, `authorization`) and anything matching an API-key pattern.
- Configuration is validated at startup; `ENV=dev` is the only mode where docs/debug helpers are enabled.

---

## 6. Testing

- pytest against a real PostgreSQL 17 (a dedicated database whose name must end in `_test`; migrated once per test session; all tables truncated by the owner role after each database test).
- **Unit:** validators (including Verhoeff), maskers, AEAD round-trip, tamper detection (nonce, AAD, ciphertext, wrapped DEK), lookup-HMAC determinism, audit chain verification (edit, delete, reorder), policy decisions, API-key hashing.
- **Property-based (Hypothesis):** encrypt/decrypt round-trip for arbitrary bytes; normalisation is idempotent.
- **Integration (HTTP):** tokenize/detokenize across policy combinations; dedup; batch limits; erasure; export; DEK rotation plus re-encryption; master rotation; rate limiting; health/readiness.
- **Security regression:** cross-tenant reads blocked by RLS even with a raw SQL query lacking a tenant filter; ciphertext copied across tenants fails to decrypt; revoked keys rejected; console POST without CSRF rejected; console login requires TOTP; lockout after five failures; logs contain no values or secrets; denied and missing tokens are indistinguishable; the app role cannot UPDATE or DELETE `audit_log`.
- **KMS adapter:** tested with `moto`.
- **Coverage:** at least 90% line coverage for `crypto`, `vault`, `policy` and `audit`, enforced in CI.

---

## 7. CI and repository

- GitHub Actions on `ubuntu-latest` with a `postgres:17` service: `uv sync --frozen`, `ruff check`, `ruff format --check`, `mypy --strict` (core modules), `pytest --cov`, `bandit`, `pip-audit`, `gitleaks`.
- Dependabot for `uv` and GitHub Actions.
- Repository contents: `README.md` (pitch, architecture diagram, quickstart, demo GIF, badges), `docs/threat-model.md`, `docs/crypto-design.md`, `docs/adr/` (FastAPI + Postgres; envelope encryption with pluggable key provider; random tokens with HMAC lookup; hash-chained audit; modular monolith), `SECURITY.md`, `LICENSE` (MIT), `.env.example`.
- Conventional commits.

### Local quickstart (target)

```
uv sync
uv run securedb init
uv run alembic upgrade head
uv run securedb seed-demo
uv run securedb serve
```

---

## 8. Milestones

Each milestone ends with the project working, tested and green in CI.

1. **Skeleton:** repo layout, config, database session with RLS context, Alembic baseline, CLI stub, health endpoints, CI pipeline.
2. **Crypto:** `KeyProvider` protocol, `LocalKeyProvider` (keychain and passphrase modes), `KeyRing`, AEAD, lookup HMAC.
3. **Vault core:** tenants and API keys, policies, validators and maskers, tokenize/detokenize API.
4. **Audit:** hash-chained append, verify endpoint, DB role grants.
5. **Lifecycle:** subject erasure and export, DEK rotation and re-encryption, master rotation.
6. **Console:** auth with TOTP, sessions, CSRF, pages, playground.
7. **Polish:** KMS adapter, `seed-demo`, docs and ADRs, README and demo GIF.
