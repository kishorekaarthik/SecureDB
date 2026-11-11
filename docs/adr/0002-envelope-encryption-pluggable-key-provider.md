# 0002: Envelope encryption with a pluggable key provider

## Decision

Values are encrypted with a per-tenant data key (DEK). DEKs are stored wrapped by a master
key held by a `KeyProvider`. Three providers exist: the OS keychain (default), a file
encrypted under an Argon2id-derived key, and AWS KMS (optional `boto3` extra).

## Why

- A database dump alone is useless: it contains ciphertext and wrapped keys.
- Per-tenant keys limit the blast radius of one key and allow per-tenant rotation.
- Master rotation re-wraps a few small keys instead of re-encrypting all data.
- The `KeyProvider` protocol (wrap, unwrap, is_unlocked) keeps the rest of the code unaware of
  where the master key lives. The local providers need no cloud account, so the project runs
  from a clone; KMS is there for production.
- If the provider cannot be unlocked the service still starts and reports `key_provider:
  false` on `/readyz`, instead of crash-looping.

## Cost

- Local providers keep the master key in process memory; KMS avoids that at the price of a
  network call per unwrap (mitigated by caching unwrapped DEKs).
- The KMS provider is tested against an in-memory fake client, not a real AWS endpoint.
- `rotate-master` is automated only for the keychain store.
