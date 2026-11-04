# KARLION Command Center

Internal operating system for KARLION: one founder, a controlled AI workforce. Modular monolith on
Next.js + Supabase, with n8n for integrations. See `docs/` for design notes.

## Status: Phase 1 foundation (in progress)

| Area | State |
|---|---|
| DB: orgs, memberships, RLS helpers, company settings, integrations, notifications, tasks | Written, **tested on vanilla PostgreSQL 16 with a Supabase stub** |
| DB: append-only audit log, transactional outbox, approvals (human-only, immutable, exactly-once), idempotency | Written, tested the same way |
| App: HMAC webhook signing/verification, idempotent inbound handler, outbox dispatcher, approval executor, env validation | Written, unit-tested (30 tests) |
| Routes: `/api/health`, `/api/integrations/n8n`, `/api/internal/outbox/dispatch` | Build OK; auth rejection smoke-tested locally. **Happy path not tested against a real Supabase** |
| Sign-in, MFA, tasks UI | **Not built yet** |
| n8n workflows, Slack, Telegram, GitHub, Vercel | **Not built, not tested.** No integration is claimed to work |
| Real Supabase project | **Not created.** Migrations have never run on Supabase itself |

## Run the checks

```bash
npm install
npm test           # unit tests (vitest)
npm run typecheck
npm run lint
npm run test:db    # migrations + SQL tests on a throwaway local Postgres 16 (needs postgres binaries)
```

`test:db` uses `supabase/tests/00_supabase_stub.sql` to fake `auth.users`, `auth.uid()` and the API
roles. It proves the SQL logic and RLS policies; it does **not** prove behaviour on Supabase
(PostgREST, GoTrue, default grants). Apply the migrations to a real project and re-verify before
relying on them.

## Configuration

Copy `.env.example` to `.env.local`. Only `NEXT_PUBLIC_*` values reach the browser. The service-role
key is read only in `src/platform/db/admin.ts`, which imports `server-only`.

## Layout

```
src/app/api/            thin route handlers
src/platform/           config, db access, webhooks, events (outbox), approvals
supabase/migrations/    forward-only SQL (apply in filename order)
supabase/tests/         SQL tests + test-only Supabase stub
docs/                   ADRs and operational notes
```

## Key rules (enforced in the database where possible)

- Every business table has `organization_id`; RLS is on; clients get only the grants they need.
- `integrations.secret_ref` is not readable by clients (column-level grant). Secrets live in env/Vault, never in rows.
- `activity_logs` is append-only (trigger blocks UPDATE/DELETE/TRUNCATE even for service_role).
- Clients cannot DELETE tasks (destructive operations go through approvals); use status `cancelled`.
- Approvals: payload and hash are immutable; only a human `auth.users` account in an owner/admin role can decide;
  execution is claimed once, atomically, and runs the stored payload.
