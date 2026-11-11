# 0005: Hash-chained audit log with external anchors

## Decision

Each tenant has an append-only audit log in which every entry stores
`SHA256(previous hash ‖ canonical entry)`. Entries are written in the same database
transaction as the operation they record. The application's database role may only insert and
select. Verification can be checked against an anchor (entry number and hash) kept outside the
database.

## Why

- Writing in the same transaction means there is never an operation without its entry or an
  entry without its operation. Rejected requests, which roll back, are recorded in a separate
  transaction.
- A compromised application cannot rewrite history: it has no UPDATE or DELETE privilege.
- A chain makes edits, middle deletions and reordering detectable by recomputation.
- Entries hold token IDs, counts and outcomes, never values, and identify erased subjects by a
  keyed reference. Erasure therefore never requires touching the log.

## What it does not prove

The chain is unkeyed. Someone with table-owner access can rewrite an entry and recompute every
later hash, or delete the newest entries, and the chain still verifies. Both are detected only
by comparing against an anchor recorded elsewhere. This is documented in the code, the API
and the console.

## Cost

- Appends for one tenant are serialised by an advisory lock, which bounds that tenant's write
  throughput.
- Outcomes are restricted to strings, integers, booleans, null, lists and string-keyed
  objects. Floats are refused because PostgreSQL's JSONB re-renders them, which would cause
  false tamper alarms.
- Verification reads the whole chain (streamed).

## Alternatives

- A keyed MAC chain: stops a database-only insider, but the key lives with the application.
- Publishing heads to an external transparency log: stronger, out of scope.
