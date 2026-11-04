import { describe, expect, it, vi } from "vitest";
import { handleSignedWebhook, type ClaimOutcome, type IdempotencyStore } from "./inbound";
import { buildSignedHeaders } from "./signing";

const SECRET = "k".repeat(32);

/** In-memory store mirroring the SQL function semantics. */
function memoryStore(): IdempotencyStore & { rows: Map<string, { hash: string; done: boolean; response?: unknown; status?: number }> } {
  const rows = new Map<string, { hash: string; done: boolean; response?: unknown; status?: number }>();
  return {
    rows,
    async claim(scope, key, hash) {
      const id = `${scope}|${key}`;
      const row = rows.get(id);
      if (!row) {
        rows.set(id, { hash, done: false });
        return { outcome: "new" as ClaimOutcome };
      }
      if (row.hash !== hash) return { outcome: "conflict" as ClaimOutcome };
      if (row.done) return { outcome: "replay" as ClaimOutcome, response: row.response, responseStatus: row.status };
      return { outcome: "in_progress" as ClaimOutcome };
    },
    async complete(scope, key, response, status) {
      Object.assign(rows.get(`${scope}|${key}`)!, { done: true, response, status });
    },
    async release(scope, key) {
      const id = `${scope}|${key}`;
      if (rows.get(id) && !rows.get(id)!.done) rows.delete(id);
    },
  };
}

function request(body: string, opts: { key?: string | null; secret?: string; nowMs?: number } = {}) {
  const h = buildSignedHeaders(opts.secret ?? SECRET, body, opts.key ?? "evt-1", opts.nowMs);
  if (opts.key === null) delete h["x-karlion-idempotency-key"];
  return new Request("https://app.test/api/integrations/n8n", { method: "POST", headers: h, body });
}

describe("handleSignedWebhook", () => {
  it("rejects unsigned/badly signed requests without running the handler", async () => {
    const handler = vi.fn();
    const res = await handleSignedWebhook(request("{}", { secret: "z".repeat(32) }), { secrets: [SECRET], scope: "s", store: memoryStore(), handler });
    expect(res.status).toBe(401);
    expect(handler).not.toHaveBeenCalled();
  });

  it("requires an idempotency key and valid JSON", async () => {
    const handler = vi.fn();
    const store = memoryStore();
    expect((await handleSignedWebhook(request("{}", { key: null }), { secrets: [SECRET], scope: "s", store, handler })).status).toBe(400);
    expect((await handleSignedWebhook(request("not json"), { secrets: [SECRET], scope: "s", store, handler })).status).toBe(400);
    expect(handler).not.toHaveBeenCalled();
  });

  it("runs the handler once and replays the stored response for duplicates", async () => {
    const handler = vi.fn().mockResolvedValue({ status: 201, body: { id: "t1" } });
    const store = memoryStore();
    const opts = { secrets: [SECRET], scope: "s", store, handler };
    const first = await handleSignedWebhook(request('{"a":1}'), opts);
    const second = await handleSignedWebhook(request('{"a":1}'), opts);
    expect(first.status).toBe(201);
    expect(second.status).toBe(201);
    expect(await second.json()).toEqual({ id: "t1" });
    expect(second.headers.get("x-idempotent-replay")).toBe("true");
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("returns 409 when a key is reused with a different body", async () => {
    const handler = vi.fn().mockResolvedValue({ status: 200, body: {} });
    const opts = { secrets: [SECRET], scope: "s", store: memoryStore(), handler };
    await handleSignedWebhook(request('{"a":1}'), opts);
    const res = await handleSignedWebhook(request('{"a":2}'), opts);
    expect(res.status).toBe(409);
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("returns 409 + retry-after for a concurrent duplicate", async () => {
    const store = memoryStore();
    await store.claim("s", "evt-1", (await import("node:crypto")).createHash("sha256").update("{}").digest("hex"));
    const res = await handleSignedWebhook(request("{}"), { secrets: [SECRET], scope: "s", store, handler: vi.fn() });
    expect(res.status).toBe(409);
    expect(res.headers.get("retry-after")).toBe("5");
  });

  it("releases the key when the handler throws, so a retry runs immediately", async () => {
    const store = memoryStore();
    const handler = vi.fn().mockRejectedValueOnce(new Error("db down")).mockResolvedValueOnce({ status: 200, body: { ok: true } });
    const opts = { secrets: [SECRET], scope: "s", store, handler };
    const err = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const first = await handleSignedWebhook(request("{}"), opts);
    expect(first.status).toBe(500);
    expect(await first.json()).toEqual({ error: "handler_failed" }); // no internal error text leaked
    const retry = await handleSignedWebhook(request("{}"), opts);
    expect(retry.status).toBe(200);
    expect(handler).toHaveBeenCalledTimes(2);
    err.mockRestore();
  });

  it("rejects oversized bodies", async () => {
    const big = JSON.stringify({ x: "a".repeat(300 * 1024) });
    const res = await handleSignedWebhook(request(big), { secrets: [SECRET], scope: "s", store: memoryStore(), handler: vi.fn() });
    expect(res.status).toBe(413);
  });
});
