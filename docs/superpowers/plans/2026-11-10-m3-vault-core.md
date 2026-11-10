# SecureDB Vault — Milestone 3 (Vault core) Plan

**Goal:** Tenants, API keys, access policies, PII validators and maskers, and the tokenize /
detokenize / delete HTTP API, with a per-key rate limit and operator CLI commands.

**Spec:** `docs/superpowers/specs/2026-09-28-securedb-vault-design.md` §1.3, §1.4, §2.6, §3, §4.1, §4.3.
**Builds on:** M2 (`feat/m2-crypto`, PR #6). This branch is stacked on it.

**Execution note:** the user asked to complete the project without per-milestone plan review,
so plans from M3 on are compact (decisions, interfaces, tests) and are executed immediately,
test-first. Full code lives in the commits.

## Decisions

| # | Decision | Why |
|---|---|---|
| D1 | API key secrets are hashed with **SHA-256** (constant-time compare), not argon2id | Keys are 190+ bits of randomness, so slow hashing adds no security; argon2id (64 MiB) on every request would be a memory/CPU DoS vector. Spec deviation, recorded for the ADR (M7). Console *passwords* (M6) stay argon2id. |
| D2 | `api_keys` has RLS with two policies: tenant isolation, plus an **auth-lookup policy** `FOR SELECT USING (prefix = NULLIF(current_setting('app.api_key_prefix', true), ''))` | Authentication happens before the tenant is known. The auth transaction can see exactly the one row whose prefix was presented, and nothing else. |
| D3 | Key format `sdb_live_<12 base62 prefix>_<32 base62 secret>`; unknown, revoked and wrong-secret keys all return the same 401 | Prefix gives O(1) lookup; uniform error prevents key enumeration. |
| D4 | Policies: `(api_key, field_type, action) -> effect`; tokenize only accepts `allow` (DB CHECK); no row = deny | Spec §3. |
| D5 | Tokenize: all items are validated and policy-checked **before** any write; any failure rejects the whole request (422 / 403) with item indexes and no values | Atomic, and never echoes PII. |
| D6 | Dedup via `INSERT … ON CONFLICT (tenant_id, type, lookup_hmac) DO NOTHING` then select | Race-free under concurrent tokenization of the same value. |
| D7 | Detokenize: per-token results; denied and missing tokens return the identical `{"error": "not_available"}` | Spec §2.6; no token enumeration. |
| D8 | `DELETE /v1/tokens/{token}` requires scope `subjects:erase` | Deletion is an erasure operation; reuses the spec's scope list. |
| D9 | `bank_account` values are objects `{account_number, ifsc}`; stored as canonical JSON; returned as an object (masked: account `X…1234`, IFSC in full) | Spec §1.3. |
| D10 | Rate limit: fixed window per API key, in-process, default 600 requests/minute (`SECUREDB_RATE_LIMIT_PER_MINUTE`), 429 + `Retry-After` | Spec §4.1; documented as single-process only. |

## Tables (migration 0003)

- `api_keys(id uuid PK, tenant_id FK, prefix text UNIQUE, secret_hash bytea, name text, scopes text[], created_at, revoked_at NULL, last_used_at NULL)` — RLS (D2); app: SELECT, INSERT, UPDATE.
- `policies(id uuid PK, tenant_id FK, api_key_id FK, field_type text, action text CHECK, effect text CHECK, UNIQUE(api_key_id, field_type, action), CHECK(action='detokenize' OR effect='allow'))` — RLS; app: SELECT, INSERT, UPDATE, DELETE.
- `tokens(token text PK, tenant_id FK, type text, subject_id text NULL, lookup_hmac bytea, ciphertext bytea, nonce bytea, key_version int, created_at; UNIQUE(tenant_id, type, lookup_hmac); INDEX(tenant_id, subject_id))` — RLS; app: SELECT, INSERT, DELETE.

All tenant predicates use `tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid`.

## Tasks

1. **Field types, validators, maskers** — `securedb/vault/fields.py`: `FieldType` (StrEnum), `normalize(type, raw) -> str`, `mask(type, normalized) -> str | dict`, `to_output(type, normalized) -> str | dict`, `FieldValidationError` (message never contains the value), Verhoeff check. Tests: valid/invalid per type, normalization, masks, Hypothesis idempotence, error messages free of input.
2. **Migration 0003 + models** — `ApiKey`, `Policy`, `Token`. Tests: RLS isolation for each table, auth-lookup policy sees only the presented prefix, grants, constraints, model/migration drift.
3. **API keys** — `securedb/tenants/api_keys.py`: `issue_api_key(session, tenant_id, name, scopes) -> IssuedKey(id, prefix, plaintext)`, `authenticate(db, header) -> AuthenticatedKey`, `revoke(session, key_id)`; `Scope` enum. Tests: issue/authenticate round trip, wrong secret/unknown prefix/revoked/malformed → same Unauthorized, last_used_at updated, plaintext never stored.
4. **Tenants + policies** — `securedb/tenants/service.py`: `create_tenant(db, keyring, name) -> uuid`; `securedb/policy/engine.py`: `Effect`, `Action`, `set_policy`, `decide(session, api_key_id, field_type, action) -> Effect`. Tests: default deny, allow/mask, tokenize+mask rejected, cross-tenant invisibility.
5. **TokenService** — `securedb/vault/service.py`: `tokenize`, `detokenize`, `delete_token`, new errors `Forbidden`, `UnprocessableEntity`. Tests: round trip per type, dedup, concurrent dedup, policy deny/mask, not_available uniformity, cross-tenant isolation, token format.
6. **HTTP API + rate limit** — `securedb/api/auth.py` (bearer dependency, scopes), `securedb/api/tokens.py`, `securedb/api/ratelimit.py`; `app.state.cipher`. Tests: end-to-end with TestClient, 401 with `WWW-Authenticate`, 403 scope, 422 without PII, 429 + Retry-After, limits 1..100.
7. **CLI** — `create-tenant`, `create-api-key`, `revoke-api-key`, `set-policy`. Tests via CliRunner with an in-memory keychain master key.
