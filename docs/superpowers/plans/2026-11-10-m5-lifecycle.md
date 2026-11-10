# SecureDB Vault — Milestone 5 (Lifecycle) Plan

**Goal:** DPDP subject erasure and export, data-key (DEK) rotation with batched
re-encryption, and master-key rotation.

**Spec:** §1.5, §2.5 (rotation), §2.6 (erase/export), §4.1 (`DELETE /v1/subjects/{id}`,
`GET /v1/subjects/{id}/export`), §4.3 (`rotate-dek`, `reencrypt`, `rotate-master`).
**Builds on:** M4 (`feat/m4-audit`), stacked branch `feat/m5-lifecycle`. Compact plan.

## Decisions

| # | Decision | Why |
|---|---|---|
| L1 | Erasure removes the subject's links; a token is hard-deleted only when no other subject still links to it | Shared values (family phone, joint account) belong to several people (M3 fix). Erasing one must not destroy another's data. |
| L2 | The audit entry for an erasure records deleted token IDs, counts and a keyed `subject_ref` (HMAC-SHA256 of the subject ID under the tenant lookup key), never the raw subject ID | Proves which subject was erased to someone who already knows the ID, without the log becoming a directory of subject IDs. |
| L3 | Export returns the subject's tokens (type, created_at, shared flag), their access history from the audit log, and values only as the calling key's detokenize policy allows (full / masked / omitted) | Spec §2.6. Export is itself audited. |
| L4 | Migration 0005 adds **column-level** grants: `UPDATE (status)` on `tenant_keys`, `UPDATE (ciphertext, nonce, key_version)` on `tokens`, `UPDATE (wrapped_dek, provider, provider_key_id)` on `tenant_keys` | Rotation needs updates; column grants keep the app unable to change token IDs, types, lookup hashes or tenants. |
| L5 | `rotate_dek` makes version N+1 active and the old active version `retiring`, in one transaction, audited | Spec §2.5. |
| L6 | `reencrypt` processes batches (`FOR UPDATE SKIP LOCKED`, default 500 rows), one transaction and one audit entry per batch; when no row references a retiring version it becomes `retired` | Resumable, safe alongside live traffic, bounded transactions. |
| L7 | `rotate_master(db, old, new)` re-wraps every tenant's DEKs and lookup key in **one** transaction (switching tenant context per tenant). CLI (keychain store): new key saved as `master-key.pending` first → commit → promote to `master-key`, old kept as `master-key.previous` | A crash at any point leaves a recoverable state; token rows are untouched. File-store rotation is documented as a manual procedure. |
| L8 | After `rotate-master`, running servers must restart (they hold the old master key) | Documented; `/readyz` stays green because cached keys keep working, but new unwraps would fail until restart. |

## Tasks

1. Migration 0005 (grants) + `KeyRing.rotate_dek` + `reencrypt` (crypto/rotation.py). Tests: new active version, old retiring, new writes use N+1, old values still decrypt, reencrypt moves all rows and retires the version, batches resumable, audit entries, app still cannot change token IDs/types.
2. `rotate_master`. Tests: all tenants re-wrapped, old provider can no longer unwrap, new can, tokens untouched, atomic on failure.
3. Subject erasure + export service (vault/subjects.py). Tests: sole-owner tokens deleted, shared tokens retained, audit subject_ref, export contents and policy-based values, cross-tenant isolation.
4. API `DELETE /v1/subjects/{id}`, `GET /v1/subjects/{id}/export`. Tests: scopes, 404 for unknown subject? (no — erasing an unknown subject returns `{deleted: 0}`; export returns empty), validation.
5. CLI `rotate-dek`, `reencrypt`, `rotate-master` (keychain pending/promote). Tests with in-memory keychain.

## Review outcome

Fresh whole-branch review: 1 Critical, 5 Important (all fixed test-first), 10 Minor (deferred).

Fixed:
1. (Critical) `rotate-master` on a file-store setup moved the key into the keychain and left the server unable to unwrap after restart while reporting success: now refused with the manual procedure.
2. A crash mid-promotion left a stale pending key, turning the next rotation into a silent no-op (X -> X) and overwriting `previous`: stage/promote now detect and finish it.
3. A mixed key state (tenant created under the old key mid-rotation) blocked rotation forever: re-wrap is idempotent per key, and a key-management advisory lock (exclusive for rotation, shared for key creation) prevents the mix; concurrent `rotate-dek` now queues.
4. Subject IDs (possibly e-mail addresses) reached uvicorn access logs via URL paths: redacted by the log processor.
5. Tokenize racing an erasure returned a foreign-key 500 (reproduced in round 1) or a deleted token: existing tokens are locked FOR KEY SHARE.
6. Export history was silently the *oldest* 1000 entries and unindexed: now the most recent window with `history_truncated`, plus a GIN index (migration 0006).

Deferred minors: `reencrypt` re-scans moved rows (no `(tenant_id, key_version)` index / keyset pagination); `reencrypt` does not report rows left on old versions or name an undecryptable token; CLI shows CryptoError as "Internal Server Error"; `rotate_master` holds every tenant's audit lock until commit (matters with KMS); "(N tenants re-wrapped)" wording; only one `previous` key generation kept; erasure's FOR UPDATE silently relies on the 0005 grant; `subject_ref` domain separation relies on no FieldType named "subject"; a few test gaps (0005 downgrade, multi-version history).
