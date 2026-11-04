# ADR 0001: Modular monolith, transactional outbox, DB-enforced invariants

Status: accepted for Phase 1 (2026-11-05)

- One Next.js app; modules talk through service functions, not each other's tables. No microservices.
- Supabase Postgres is the only system of record. Slack and Telegram hold no state.
- State changes and their events commit atomically via `outbox_events`; a dispatcher delivers signed webhooks to n8n
  with the event id as idempotency key. Delivery is at-least-once, so n8n workflows must de-duplicate on that key.
- Invariants that must never be bypassed (audit immutability, approval immutability and single execution, human-only
  approval, secret column privacy) live in the database, not only in application code.
- `organization_id` on every table from day one so multi-tenancy is a product change, not a rewrite.

Known limitation: audit rows written through PostgREST service-role calls are attributed to `system`
unless the caller sets `app.actor_type`/`app.actor_id` in the same transaction (needs an RPC wrapper; not built).
