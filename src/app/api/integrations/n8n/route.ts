import { z } from "zod";
import { serverEnv } from "@/platform/config/env";
import { adminClient, idempotencyStore } from "@/platform/db/admin";
import { handleSignedWebhook } from "@/platform/webhooks/inbound";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const message = z.discriminatedUnion("type", [
  z.object({ type: z.literal("ping") }),
  z.object({
    type: z.literal("task.create"),
    organization_id: z.string().uuid(),
    title: z.string().trim().min(1).max(300),
    description: z.string().max(5000).optional(),
    priority: z.enum(["low", "normal", "high", "urgent"]).default("normal"),
    due_at: z.string().datetime().optional(),
  }),
]);

/** n8n -> KARLION. Signed, replay-protected and idempotent. n8n never gets database credentials. */
export async function POST(req: Request) {
  const secret = serverEnv().N8N_INBOUND_SIGNING_SECRET;
  if (!secret) return Response.json({ error: "not_configured" }, { status: 503 });

  return handleSignedWebhook(req, {
    secrets: [secret],
    scope: "n8n:inbound",
    store: idempotencyStore(),
    handler: async (raw) => {
      const parsed = message.safeParse(raw);
      if (!parsed.success) return { status: 422, body: { error: "invalid_message", issues: parsed.error.issues.map((i) => i.message) } };
      const msg = parsed.data;
      if (msg.type === "ping") return { status: 200, body: { ok: true } };

      const { data, error } = await adminClient()
        .from("tasks")
        .insert({
          organization_id: msg.organization_id,
          title: msg.title,
          description: msg.description,
          priority: msg.priority,
          due_at: msg.due_at,
        })
        .select("id")
        .single();
      if (error) throw new Error(error.message);
      return { status: 201, body: { task_id: data.id } };
    },
  });
}
