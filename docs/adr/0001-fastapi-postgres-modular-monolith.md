# 0001: FastAPI + PostgreSQL as a modular monolith

## Decision

One FastAPI process and one PostgreSQL database. Code is split into modules with narrow
interfaces (`crypto`, `vault`, `policy`, `audit`, `tenants`, `api`, `console`, `cli`).
SQLAlchemy is used synchronously.

## Why

- PostgreSQL gives the two properties the design leans on: **row-level security**, so tenant
  isolation is enforced by the database and not only by application code, and **transactions**,
  so an operation and its audit entry commit together or not at all.
- FastAPI produces an OpenAPI description from typed request models, which an API-first
  product needs.
- A monolith keeps the audit-in-the-same-transaction guarantee simple. Splitting the audit log
  into its own service would turn it into a distributed transaction.
- Synchronous database code: the workload is short queries plus CPU-bound cryptography, and
  sync sessions make the transaction-local tenant context easy to reason about.

## Cost

- Rate limits and the key cache are per process, so horizontal scaling needs a shared store.
- A long-running operation (re-encryption from the console) occupies a worker thread.

## Alternatives

- Flask + MongoDB (the original project): no row-level security, weaker transactions.
- Separate tokenization and audit services: more moving parts for no gain at this scale.
