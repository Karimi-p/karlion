import { describe, expect, it, vi } from "vitest";
import { dispatchOutbox, type OutboxRow, type OutboxStore } from "./dispatcher";
import { verifySignature } from "@/platform/webhooks/signing";

const SECRET = "d".repeat(32);
const row = (id: string): OutboxRow => ({
  id, organization_id: "org", event_type: "task.created", aggregate_type: "task", aggregate_id: "t1",
  payload: { title: "x" }, attempts: 1, created_at: "2026-11-05T00:00:00Z",
});

function store(rows: OutboxRow[]): OutboxStore & { delivered: string[]; failed: [string, string][] } {
  const s = {
    delivered: [] as string[], failed: [] as [string, string][],
    claim: vi.fn(async () => rows),
    markDelivered: vi.fn(async (id: string) => { s.delivered.push(id); }),
    markFailed: vi.fn(async (id: string, e: string) => { s.failed.push([id, e]); }),
  };
  return s;
}

describe("dispatchOutbox", () => {
  it("does nothing (and claims nothing) when n8n is not configured", async () => {
    const s = store([row("a")]);
    const r = await dispatchOutbox({ store: s, url: undefined, secret: undefined });
    expect(r).toEqual({ skipped: true, claimed: 0, delivered: 0, failed: 0 });
    expect(s.claim).not.toHaveBeenCalled();
  });

  it("posts signed events with the event id as idempotency key", async () => {
    const s = store([row("evt-1")]);
    const fetchImpl = vi.fn(async (_u: unknown, init?: RequestInit) => {
      const h = init!.headers as Record<string, string>;
      expect(h["x-karlion-idempotency-key"]).toBe("evt-1");
      const v = verifySignature({ secrets: [SECRET], body: init!.body as string, timestamp: h["x-karlion-timestamp"], signature: h["x-karlion-signature"] });
      expect(v.ok).toBe(true);
      expect(JSON.parse(init!.body as string)).toMatchObject({ id: "evt-1", type: "task.created", data: { title: "x" } });
      return new Response("ok", { status: 200 });
    });
    const r = await dispatchOutbox({ store: s, url: "https://n8n.test/webhook/x", secret: SECRET, fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(r).toMatchObject({ claimed: 1, delivered: 1, failed: 0 });
    expect(s.delivered).toEqual(["evt-1"]);
  });

  it("marks non-2xx responses and network errors as failed, per event", async () => {
    const s = store([row("ok"), row("bad"), row("net")]);
    const fetchImpl = vi.fn(async (_u: unknown, init?: RequestInit) => {
      const id = JSON.parse(init!.body as string).id;
      if (id === "bad") return new Response("no", { status: 502 });
      if (id === "net") throw new Error("ECONNRESET");
      return new Response("ok");
    });
    const r = await dispatchOutbox({ store: s, url: "https://n8n.test/x", secret: SECRET, fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(r).toMatchObject({ claimed: 3, delivered: 1, failed: 2 });
    expect(s.failed).toEqual(expect.arrayContaining([["bad", "n8n responded with HTTP 502"], ["net", "ECONNRESET"]]));
  });

  it("passes a timeout signal to fetch", async () => {
    const s = store([row("a")]);
    let signal: AbortSignal | undefined;
    const fetchImpl = vi.fn(async (_u: unknown, init?: RequestInit) => { signal = init!.signal as AbortSignal; return new Response("ok"); });
    await dispatchOutbox({ store: s, url: "https://n8n.test/x", secret: SECRET, timeoutMs: 1234, fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(signal).toBeInstanceOf(AbortSignal);
  });
});
