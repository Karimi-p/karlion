import { describe, expect, it } from "vitest";
import { loadServerEnv } from "./env";

const base = {
  NEXT_PUBLIC_SUPABASE_URL: "https://abc.supabase.co",
  NEXT_PUBLIC_SUPABASE_ANON_KEY: "anon",
  SUPABASE_SERVICE_ROLE_KEY: "service",
};

describe("loadServerEnv", () => {
  it("accepts the minimum config (n8n optional)", () => {
    expect(loadServerEnv(base).N8N_OUTBOUND_WEBHOOK_URL).toBeUndefined();
  });
  it("treats empty strings from .env as unset", () => {
    expect(loadServerEnv({ ...base, N8N_OUTBOUND_WEBHOOK_URL: "", N8N_INBOUND_SIGNING_SECRET: "" }).N8N_INBOUND_SIGNING_SECRET).toBeUndefined();
  });
  it("requires the service role key", () => {
    expect(() => loadServerEnv({ ...base, SUPABASE_SERVICE_ROLE_KEY: "" })).toThrow(/SUPABASE_SERVICE_ROLE_KEY/);
  });
  it("rejects short signing secrets without echoing them", () => {
    const bad = "short-secret-value";
    try {
      loadServerEnv({ ...base, N8N_INBOUND_SIGNING_SECRET: bad });
      throw new Error("should have thrown");
    } catch (e) {
      expect((e as Error).message).toMatch(/N8N_INBOUND_SIGNING_SECRET/);
      expect((e as Error).message).not.toContain(bad);
    }
  });
  it("requires a signing secret when an outbound URL is set, and https", () => {
    expect(() => loadServerEnv({ ...base, N8N_OUTBOUND_WEBHOOK_URL: "https://n8n.example.com/webhook/x" })).toThrow(/N8N_OUTBOUND_SIGNING_SECRET/);
    expect(() => loadServerEnv({ ...base, N8N_OUTBOUND_WEBHOOK_URL: "http://n8n.example.com/x", N8N_OUTBOUND_SIGNING_SECRET: "s".repeat(32) })).toThrow(/https/);
    expect(loadServerEnv({ ...base, N8N_OUTBOUND_WEBHOOK_URL: "http://localhost:5678/x", N8N_OUTBOUND_SIGNING_SECRET: "s".repeat(32) })).toBeTruthy();
  });
});
