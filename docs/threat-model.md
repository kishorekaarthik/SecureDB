# Threat model

SecureDB Vault stores sensitive values (PAN, Aadhaar, bank accounts, phone numbers, e-mail
addresses) for several tenants and hands their applications opaque tokens instead. This
document lists what it defends against, how, and what it deliberately does not defend.

## Assets

| Asset | Where it lives |
|---|---|
| Plaintext values | Only in process memory while a request is served |
| Master key | OS keychain, a passphrase-encrypted file, or AWS KMS. Never in the database |
| Tenant data keys and lookup keys | Database, wrapped (encrypted) by the master key |
| API key secrets | Shown once at creation; the database holds a SHA-256 hash |
| Console passwords and TOTP secrets | Argon2id hash; TOTP secret encrypted with the tenant data key |
| Audit log | Database, append-only for the application role, hash-chained per tenant |

## Actors

- **Tenant application** holding an API key with scopes and per-field policies.
- **Console user** of one tenant: `owner` (may change things) or `viewer` (read-only).
- **Operator** with the CLI, the master key and database credentials.
- **Attackers**: an outsider with network access, a tenant trying to reach another tenant's
  data, someone holding a stolen database dump or API key, and an insider with database access.

## Threats and mitigations

| Threat | Mitigation | Where |
|---|---|---|
| Stolen database dump | Values are AES-256-GCM ciphertext; data keys are wrapped by a master key that is not in the database | `crypto/` |
| Ciphertext or wrapped key moved between tenants, tokens or versions | Tenant, token, type and key version are bound in as associated data, so decryption fails | `crypto/values.py`, `crypto/tenant_keys.py` |
| One tenant reads another's rows through an application bug | Forced PostgreSQL row-level security on every tenant table, keyed on a transaction-local setting; the key ring also refuses to release a tenant's keys outside that tenant's context | migrations, `db/session.py` |
| Leaked API key | Hashed at rest, scoped, revocable, `last_used_at` recorded; deny-by-default policies limit what it can read | `tenants/api_keys.py`, `policy/` |
| Guessing which tokens exist | Denied and unknown tokens return the same `not_available` result | `vault/service.py` |
| Values leaking through errors or logs | Validation errors never include input; database errors are logged without their message or parameters; a log processor redacts sensitive keys, API keys and subject IDs in URL paths | `errors.py`, `logs.py` |
| Insider edits or deletes audit entries | Per-tenant hash chain; the application role can only insert and select; `verify` pinpoints the first broken entry | `audit/log.py` |
| Insider rewrites the whole audit log, or truncates the newest entries | Detectable only against an anchor (entry number and hash) kept outside the database; `verify` accepts one | `audit/log.py` |
| Console session theft, CSRF, clickjacking, XSS | Hashed server-side sessions in `__Host-` cookies (HttpOnly, Secure, SameSite=Strict); CSRF token on every POST; TOTP second factor; no JavaScript and a `default-src 'none'` CSP; auto-escaped templates; frame and referrer headers | `console/`, `middleware.py` |
| Password guessing | Argon2id; five failures lock the account for 15 minutes; logins are rate limited per client and per account | `console/auth.py` |
| Resource exhaustion by anonymous clients | Request bodies capped before parsing; per-key API rate limit; login throttle; password hashing runs with no database connection held | `middleware.py`, `api/ratelimit.py` |
| Tampered master key file | Authenticated encryption; KDF cost parameters are bounded before use | `crypto/master_key.py` |

## Not defended

- **An attacker who controls the running process** (memory inspection, code execution on the
  server). Unwrapped keys live in memory while the service runs.
- **A malicious operator** who holds the master key and database owner credentials.
- **Network-level denial of service.** Rate limits are in-process and per instance.
- **Account lockout as denial of service.** Anyone who knows a tenant name and e-mail can keep
  that console account locked; operators recover it with `securedb unlock-user`.
- **Deployment hardening**: TLS termination, host security, backups and secret distribution are
  the operator's responsibility. Serve the API and console only over HTTPS.

## Operational guidance

- Record the audit head (entry number and hash from `verify`) somewhere the database owner
  cannot change, and verify against it periodically.
- After `rotate-master`, restart running servers: they still hold the old key.
- Rotate tenant data keys periodically (`rotate-dek`, then `reencrypt`); see
  [crypto-design.md](crypto-design.md) for the nonce budget that motivates this.
