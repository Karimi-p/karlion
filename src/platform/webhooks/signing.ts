import { createHmac, timingSafeEqual } from "node:crypto";

export const SIGNATURE_HEADER = "x-karlion-signature";
export const TIMESTAMP_HEADER = "x-karlion-timestamp";
export const IDEMPOTENCY_HEADER = "x-karlion-idempotency-key";
export const DEFAULT_TOLERANCE_SECONDS = 300;

/** HMAC-SHA256 over `${unixSeconds}.${rawBody}`. Binding the timestamp stops replay of old captures. */
export function signPayload(secret: string, timestampSeconds: number, body: string): string {
  return "v1=" + createHmac("sha256", secret).update(`${timestampSeconds}.${body}`).digest("hex");
}

export function buildSignedHeaders(
  secret: string,
  body: string,
  idempotencyKey: string,
  nowMs: number = Date.now(),
): Record<string, string> {
  const ts = Math.floor(nowMs / 1000);
  return {
    "content-type": "application/json",
    [TIMESTAMP_HEADER]: String(ts),
    [SIGNATURE_HEADER]: signPayload(secret, ts, body),
    [IDEMPOTENCY_HEADER]: idempotencyKey,
  };
}

export type VerifyFailure = "missing_headers" | "stale_timestamp" | "bad_signature";
export type VerifyResult = { ok: true } | { ok: false; reason: VerifyFailure };

/** Accepts several secrets so a key can be rotated without downtime. */
export function verifySignature(args: {
  secrets: string[];
  body: string;
  timestamp: string | null | undefined;
  signature: string | null | undefined;
  nowMs?: number;
  toleranceSeconds?: number;
}): VerifyResult {
  const { secrets, body, timestamp, signature } = args;
  if (!timestamp || !signature || secrets.length === 0) return { ok: false, reason: "missing_headers" };

  const ts = Number(timestamp);
  if (!Number.isInteger(ts)) return { ok: false, reason: "missing_headers" };
  const now = Math.floor((args.nowMs ?? Date.now()) / 1000);
  if (Math.abs(now - ts) > (args.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS)) {
    return { ok: false, reason: "stale_timestamp" };
  }

  const given = Buffer.from(signature);
  for (const secret of secrets) {
    const expected = Buffer.from(signPayload(secret, ts, body));
    if (expected.length === given.length && timingSafeEqual(expected, given)) return { ok: true };
  }
  return { ok: false, reason: "bad_signature" };
}
