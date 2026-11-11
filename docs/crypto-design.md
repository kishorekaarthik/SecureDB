# Cryptographic design

## Key hierarchy

```
Master key  (OS keychain | passphrase file | AWS KMS; never in the database)
  ├─ wraps → tenant data key (DEK), versioned, one active per tenant
  │            └─ encrypts → token values and console TOTP secrets (AES-256-GCM)
  └─ wraps → tenant lookup key
               └─ HMAC-SHA256 → dedup lookup hash, subject reference in audit entries
```

This is envelope encryption: values are encrypted with a per-tenant key, and that key is
stored only in wrapped form. Compromising the database alone yields ciphertext. Rotating the
master key re-wraps a handful of small keys instead of re-encrypting every value.

## Primitives

| Purpose | Primitive | Notes |
|---|---|---|
| Value and key encryption | AES-256-GCM | 96-bit random nonce per encryption, 128-bit tag. All calls go through `crypto/aead.py` |
| Passphrase → key (file store) | Argon2id | t=3, m=64 MiB, p=4; parameters stored in the file and bounded when read |
| Lookup hash | HMAC-SHA256 | Keyed per tenant; over the field type and normalised value |
| Console passwords | Argon2id | `argon2-cffi` defaults |
| API key secrets | SHA-256 | Secrets are ~190 random bits, so a fast hash suffices (ADR 0003) |
| Audit chain | SHA-256 | `hash = SHA256(prev_hash ‖ canonical_json(entry))` |
| Randomness | `os.urandom` / `secrets` | Keys, nonces, tokens, session IDs |

## Associated data (what each ciphertext is bound to)

Associated data is a canonical JSON encoding of a label plus sorted fields, so two different
contexts can never encode to the same bytes.

| Ciphertext | Bound to |
|---|---|
| Token value | tenant ID, token, field type, DEK version |
| Wrapped DEK | purpose `dek`, tenant ID, DEK version, and (local providers) master key ID |
| Wrapped lookup key | purpose `lookup`, tenant ID, and (local providers) master key ID |
| Console TOTP secret | tenant ID, `console_user:<id>`, field `console_totp`, DEK version |
| Master key file | key ID (KDF parameters are implicitly authenticated: changing them changes the derived key) |

Consequences, each covered by tests: a value copied to another tenant, token or type fails to
decrypt; a wrapped key copied to another tenant or version fails to unwrap.

With AWS KMS the purpose, tenant and version are sent as the KMS *encryption context*, so KMS
enforces the same binding and records it in CloudTrail. The master key is bound by KMS itself
(the ciphertext identifies its key, and the provider pins `KeyId` on decrypt), so no master
key ID is added to the context.

## Nonces and the reason for rotation

Nonces are random 96-bit values. NIST SP 800-38D limits a key used with random nonces to
2^32 encryptions, which keeps the probability of a nonce repeat below about 2^-32. Each tenant
has its own DEK and `rotate-dek` starts a fresh one, so the limit applies per tenant per key
version. Everything encrypted under a DEK counts: token values, console TOTP secrets, and
values re-encrypted onto it. The vault does not count encryptions, so rotate on a schedule
sized to the tenant's volume.

## Tokens and deduplication

Tokens are random (`tok_<type>_` + 22 base62 characters, about 131 bits) and carry no
information about the value. To return the same token when the same value is tokenized again,
the vault stores `HMAC(lookup key, type ‖ normalised value)` with a unique constraint per
tenant and type. The lookup key is separate from the DEKs and is not rotated by DEK rotation,
because rotating it would break deduplication. It is re-wrapped on master rotation.

Trade-off: someone holding the lookup key and the database can test guesses for low-entropy
values (a phone number) offline. The lookup key is wrapped by the master key, so this requires
compromising the master key as well.

## Rotation

- **Data key** (`rotate-dek`): a new version becomes active; the previous one becomes
  `retiring` and keeps decrypting. `reencrypt` moves values in batches (`FOR UPDATE SKIP
  LOCKED`, one audited transaction per batch), is safe beside live traffic and resumable, and
  marks versions nothing uses as `retired`.
- **Master key** (`rotate-master`, keychain store): the new key is saved as *pending*, every
  tenant's keys are re-wrapped in one transaction, then the pending key is promoted and the old
  one kept as *previous*. Re-wrapping is idempotent per key, and a key-management lock stops
  keys being created under the old master key meanwhile, so an interrupted rotation can simply
  be re-run. Token rows are not touched.

## Audit chain guarantees

Each tenant has its own chain starting from 32 zero bytes. Appends are serialised with a
transaction-scoped advisory lock, written in the same transaction as the operation they
describe, and contain token IDs and outcomes but never values.

`verify` detects edits, deletions in the middle and reordering by anyone who cannot recompute
every later hash. The chain is unkeyed, so **truncating the newest entries or rewriting the
whole chain with table-owner access is only detectable against an anchor** stored outside the
database. `verify` accepts such an anchor.

## Known limits

- Unwrapped keys are cached in process memory for the life of the process.
- Python cannot reliably zero key material after use.
- The in-process cache means running servers must be restarted after master rotation.
