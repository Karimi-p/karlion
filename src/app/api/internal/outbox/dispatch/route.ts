import { serverEnv } from "@/platform/config/env";
import { outboxStore } from "@/platform/db/admin";
import { dispatchOutbox } from "@/platform/events/dispatcher";
import { SIGNATURE_HEADER, TIMESTAMP_HEADER, verifySignature } from "@/platform/webhooks/signing";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

/**
 * Drains the outbox. Called on a schedule by an authenticated caller (same HMAC scheme as n8n).
 * Who calls it, and how often, is a deployment decision documented in docs/outbox-scheduling.md.
 */
export async function POST(req: Request) {
  const env = serverEnv();
  if (!env.N8N_INBOUND_SIGNING_SECRET) return Response.json({ error: "not_configured" }, { status: 503 });
  const body = await req.text();
  const verdict = verifySignature({
    secrets: [env.N8N_INBOUND_SIGNING_SECRET],
    body,
    timestamp: req.headers.get(TIMESTAMP_HEADER),
    signature: req.headers.get(SIGNATURE_HEADER),
  });
  if (!verdict.ok) return Response.json({ error: "unauthorized" }, { status: 401 });

  const result = await dispatchOutbox({
    store: outboxStore(),
    url: env.N8N_OUTBOUND_WEBHOOK_URL,
    secret: env.N8N_OUTBOUND_SIGNING_SECRET,
  });
  return Response.json(result);
}
