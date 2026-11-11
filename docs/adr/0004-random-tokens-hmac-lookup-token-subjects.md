# 0004: Random tokens, HMAC lookup, and a token–subject link table

## Decision

- Tokens are random and unrelated to the value.
- Deduplication uses a per-tenant keyed hash (`HMAC-SHA256`) of the type and normalised value,
  with a unique constraint.
- A token can be linked to several data subjects through a `token_subjects` table. Erasing a
  subject removes that subject's links and deletes a token only when no other subject still
  links to it.

## Why

- Random tokens leak nothing and need no format-preserving encryption.
- Tokenizing the same value twice should give the same token, so tenants can join on tokens.
  A keyed hash allows that without storing anything reversible, and other tenants' hashes of
  the same value differ.
- The first design stored one `subject_id` on the token row. A review showed this breaks DPDP
  erasure for shared values (a family phone number, a joint account): the second subject was
  silently dropped, so erasing one person either kept their data or deleted someone else's.

## Cost

- Only exact-match lookup is possible; no search or range queries.
- The lookup key cannot be rotated without recomputing every hash, so DEK rotation leaves it
  alone.
- `created: false` tells a caller with tokenize rights that the value was already in the
  tenant's vault.
- A token tokenized without a subject and later linked to exactly one subject is deleted when
  that subject is erased.

## Concurrency notes

Batches insert in a canonical order so that concurrent batches sharing values cannot deadlock.
Existing tokens are locked `FOR KEY SHARE` during tokenization so a concurrent erasure cannot
delete a token that is about to be returned.
