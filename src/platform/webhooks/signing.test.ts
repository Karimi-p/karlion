import { describe, expect, it } from "vitest";
import { buildSignedHeaders, signPayload, verifySignature, SIGNATURE_HEADER, TIMESTAMP_HEADER } from "./signing";

const SECRET = "s".repeat(32);
const NOW = 1_800_000_000_000;

function headers(body: string, secret = SECRET, nowMs = NOW) {
  const h = buildSignedHeaders(secret, body, "evt-1", nowMs);
  return { timestamp: h[TIMESTAMP_HEADER], signature: h[SIGNATURE_HEADER] };
}

describe("webhook signing", () => {
  it("accepts a correctly signed body", () => {
    const body = '{"a":1}';
    expect(verifySignature({ secrets: [SECRET], body, ...headers(body), nowMs: NOW }).ok).toBe(true);
  });

  it("rejects a tampered body", () => {
    const h = headers('{"a":1}');
    const r = verifySignature({ secrets: [SECRET], body: '{"a":2}', ...h, nowMs: NOW });
    expect(r).toEqual({ ok: false, reason: "bad_signature" });
  });

  it("rejects the wrong secret", () => {
    const body = "{}";
    const r = verifySignature({ secrets: ["x".repeat(32)], body, ...headers(body), nowMs: NOW });
    expect(r.ok).toBe(false);
  });

  it("rejects stale and future timestamps (replay window)", () => {
    const body = "{}";
    const h = headers(body);
    expect(verifySignature({ secrets: [SECRET], body, ...h, nowMs: NOW + 301_000 })).toEqual({ ok: false, reason: "stale_timestamp" });
    expect(verifySignature({ secrets: [SECRET], body, ...h, nowMs: NOW - 301_000 })).toEqual({ ok: false, reason: "stale_timestamp" });
    expect(verifySignature({ secrets: [SECRET], body, ...h, nowMs: NOW + 299_000 }).ok).toBe(true);
  });

  it("cannot reuse a signature with a different timestamp", () => {
    const body = "{}";
    const sig = headers(body).signature;
    const r = verifySignature({ secrets: [SECRET], body, timestamp: String(NOW / 1000 + 10), signature: sig, nowMs: NOW });
    expect(r).toEqual({ ok: false, reason: "bad_signature" });
  });

  it("rejects missing or malformed headers and empty secret lists", () => {
    expect(verifySignature({ secrets: [SECRET], body: "", timestamp: null, signature: null }).ok).toBe(false);
    expect(verifySignature({ secrets: [SECRET], body: "", timestamp: "abc", signature: "v1=00" }).ok).toBe(false);
    expect(verifySignature({ secrets: [], body: "", ...headers("") , nowMs: NOW }).ok).toBe(false);
  });

  it("does not throw on signatures of a different length", () => {
    const r = verifySignature({ secrets: [SECRET], body: "{}", timestamp: String(NOW / 1000), signature: "v1=short", nowMs: NOW });
    expect(r).toEqual({ ok: false, reason: "bad_signature" });
  });

  it("supports secret rotation (any listed secret verifies)", () => {
    const old = "o".repeat(32);
    const body = "{}";
    expect(verifySignature({ secrets: [SECRET, old], body, ...headers(body, old), nowMs: NOW }).ok).toBe(true);
  });

  it("is deterministic and versioned", () => {
    expect(signPayload(SECRET, 1, "x")).toBe(signPayload(SECRET, 1, "x"));
    expect(signPayload(SECRET, 1, "x")).toMatch(/^v1=[0-9a-f]{64}$/);
  });
});
