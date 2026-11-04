import { buildSignedHeaders } from "@/platform/webhooks/signing";

export interface OutboxRow {
  id: string;
  organization_id: string;
  event_type: string;
  aggregate_type: string;
  aggregate_id: string | null;
  payload: unknown;
  attempts: number;
  created_at: string;
}

export interface OutboxStore {
  claim(limit: number, leaseSeconds: number): Promise<OutboxRow[]>;
  markDelivered(id: string): Promise<void>;
  markFailed(id: string, error: string, maxAttempts: number): Promise<void>;
}

export interface DispatchResult {
  skipped: boolean;
  claimed: number;
  delivered: number;
  failed: number;
}

/**
 * Delivers queued events to n8n as signed webhooks. The event id is the idempotency key,
 * so a retry after a timeout cannot cause n8n to process the same event twice (n8n workflows
 * must de-duplicate on this header). Retries/backoff/dead-lettering live in the database functions.
 */
export async function dispatchOutbox(opts: {
  store: OutboxStore;
  url: string | undefined;
  secret: string | undefined;
  limit?: number;
  timeoutMs?: number;
  maxAttempts?: number;
  fetchImpl?: typeof fetch;
  nowMs?: () => number;
}): Promise<DispatchResult> {
  // Not configured: leave events queued rather than burning attempts.
  if (!opts.url || !opts.secret) return { skipped: true, claimed: 0, delivered: 0, failed: 0 };

  const doFetch = opts.fetchImpl ?? fetch;
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const maxAttempts = opts.maxAttempts ?? 8;
  const rows = await opts.store.claim(opts.limit ?? 20, Math.ceil(timeoutMs / 1000) + 30);

  let delivered = 0;
  let failed = 0;
  await Promise.all(
    rows.map(async (row) => {
      const body = JSON.stringify({
        id: row.id,
        type: row.event_type,
        organization_id: row.organization_id,
        aggregate: { type: row.aggregate_type, id: row.aggregate_id },
        occurred_at: row.created_at,
        attempt: row.attempts,
        data: row.payload,
      });
      try {
        const res = await doFetch(opts.url as string, {
          method: "POST",
          headers: buildSignedHeaders(opts.secret as string, body, row.id, opts.nowMs?.()),
          body,
          signal: AbortSignal.timeout(timeoutMs),
        });
        if (!res.ok) throw new Error(`n8n responded with HTTP ${res.status}`);
        await opts.store.markDelivered(row.id);
        delivered++;
      } catch (err) {
        failed++;
        const message = err instanceof Error ? err.message : "unknown delivery error";
        await opts.store.markFailed(row.id, message, maxAttempts);
      }
    }),
  );
  return { skipped: false, claimed: rows.length, delivered, failed };
}
