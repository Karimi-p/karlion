# Outbox scheduling (open decision)

Events are written to `outbox_events` in the same transaction as the change. Something must call
`POST /api/internal/outbox/dispatch` (signed with `N8N_INBOUND_SIGNING_SECRET`) regularly.

Vercel Hobby cron runs at most once a day, which is too slow for alerts. Candidate callers, none yet tested here:

1. Supabase `pg_cron` + `pg_net` calling the endpoint every minute (free, no n8n executions used).
2. An n8n schedule trigger (uses execution quota: ~43,000/month at one per minute, over every cloud tier except self-hosted).
3. Inline best-effort dispatch after a write, plus a slower sweep as backstop.

Recommendation: option 1 with option 3 as latency optimisation. Verify on a real project before relying on it.
