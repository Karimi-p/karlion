import { createHash } from "node:crypto";
import { IDEMPOTENCY_HEADER, SIGNATURE_HEADER, TIMESTAMP_HEADER, verifySignature } from "./signing";

export type ClaimOutcome = "new" | "replay" | "in_progress" | "conflict";

export interface IdempotencyStore {
  claim(scope: string, key: string, requestHash: string): Promise<{ outcome: ClaimOutcome; response?: unknown; responseStatus?: number }>;
  complete(scope: string, key: string, response: unknown, status: number): Promise<void>;
  release(scope: string, key: string): Promise<void>;
}

export interface HandlerResult {
  status: number;
  body: unknown;
}

const MAX_BODY_BYTES = 256 * 1024;

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
}

/**
 * Authenticated, idempotent webhook receiver:
 * verify HMAC + timestamp -> require idempotency key -> claim -> run handler -> store the response.
 * A duplicate delivery returns the original response and never runs the handler twice.
 * If the handler throws, the key is released so the sender's retry is processed right away.
 */
export async function handleSignedWebhook(
  req: Request,
  opts: {
    secrets: string[];
    scope: string;
    store: IdempotencyStore;
    handler: (body: unknown) => Promise<HandlerResult>;
    nowMs?: number;
  },
): Promise<Response> {
  const declared = Number(req.headers.get("content-length") ?? 0);
  if (declared > MAX_BODY_BYTES) return json(413, { error: "payload_too_large" });
  const raw = await req.text();
  if (Buffer.byteLength(raw) > MAX_BODY_BYTES) return json(413, { error: "payload_too_large" });

  const verdict = verifySignature({
    secrets: opts.secrets,
    body: raw,
    timestamp: req.headers.get(TIMESTAMP_HEADER),
    signature: req.headers.get(SIGNATURE_HEADER),
    nowMs: opts.nowMs,
  });
  // Same status for every failure so a caller cannot learn which check failed.
  if (!verdict.ok) return json(401, { error: "unauthorized" });

  const key = req.headers.get(IDEMPOTENCY_HEADER);
  if (!key || key.length > 200) return json(400, { error: "missing_idempotency_key" });

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return json(400, { error: "invalid_json" });
  }

  const requestHash = createHash("sha256").update(raw).digest("hex");
  const claim = await opts.store.claim(opts.scope, key, requestHash);
  if (claim.outcome === "conflict") return json(409, { error: "idempotency_key_reused_with_different_body" });
  if (claim.outcome === "in_progress") return json(409, { error: "request_in_progress" }, { "retry-after": "5" });
  if (claim.outcome === "replay") {
    return json(claim.responseStatus ?? 200, claim.response ?? {}, { "x-idempotent-replay": "true" });
  }

  try {
    const result = await opts.handler(parsed);
    await opts.store.complete(opts.scope, key, result.body, result.status);
    return json(result.status, result.body);
  } catch (err) {
    await opts.store.release(opts.scope, key).catch(() => undefined);
    console.error("webhook handler failed", { scope: opts.scope, key, message: err instanceof Error ? err.message : "unknown" });
    return json(500, { error: "handler_failed" });
  }
}
