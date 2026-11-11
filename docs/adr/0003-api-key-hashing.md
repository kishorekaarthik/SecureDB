# 0003: SHA-256, not Argon2id, for API key secrets

## Decision

API keys look like `sdb_live_<12-char prefix>_<32-char secret>`. The prefix finds the row; the
database stores SHA-256 of the secret, compared in constant time. This deviates from the
original design, which called for Argon2id.

## Why

- Slow hashes exist to protect **low-entropy** secrets such as passwords. The secret here is
  32 random base62 characters, about 190 bits. Guessing it is infeasible regardless of hash
  speed.
- API keys are verified on **every request**. Argon2id at 64 MiB and ~100 ms per verification
  would cap throughput and hand any client with a well-formed bogus key a cheap way to exhaust
  memory and CPU.
- Console passwords, which people choose, do use Argon2id.

## Cost

- If the secret generator were ever weakened, a fast hash would offer no second line of
  defence. The generator is `secrets.choice` over a 62-character alphabet.

## Related

Unknown, revoked and wrong-secret keys all return the same 401, and a dummy hash is compared
when the prefix is unknown, so the response does not reveal which prefixes exist.
