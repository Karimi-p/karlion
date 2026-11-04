import { z } from "zod";

const secret = z.string().min(32, "must be at least 32 characters (openssl rand -hex 32)");

const serverSchema = z
  .object({
    NEXT_PUBLIC_SUPABASE_URL: z.string().url(),
    NEXT_PUBLIC_SUPABASE_ANON_KEY: z.string().min(1),
    SUPABASE_SERVICE_ROLE_KEY: z.string().min(1),
    N8N_OUTBOUND_WEBHOOK_URL: z.string().url().optional().or(z.literal("").transform(() => undefined)),
    N8N_OUTBOUND_SIGNING_SECRET: secret.optional().or(z.literal("").transform(() => undefined)),
    N8N_INBOUND_SIGNING_SECRET: secret.optional().or(z.literal("").transform(() => undefined)),
  })
  .superRefine((env, ctx) => {
    if (env.N8N_OUTBOUND_WEBHOOK_URL && !env.N8N_OUTBOUND_SIGNING_SECRET) {
      ctx.addIssue({ code: "custom", path: ["N8N_OUTBOUND_SIGNING_SECRET"], message: "required when N8N_OUTBOUND_WEBHOOK_URL is set" });
    }
    if (env.N8N_OUTBOUND_WEBHOOK_URL && !env.N8N_OUTBOUND_WEBHOOK_URL.startsWith("https://") && !isLocal(env.N8N_OUTBOUND_WEBHOOK_URL)) {
      ctx.addIssue({ code: "custom", path: ["N8N_OUTBOUND_WEBHOOK_URL"], message: "must use https (http allowed only for localhost)" });
    }
  });

function isLocal(url: string): boolean {
  try {
    const h = new URL(url).hostname;
    return h === "localhost" || h === "127.0.0.1";
  } catch {
    return false;
  }
}

export type ServerEnv = z.infer<typeof serverSchema>;

/** Validates env vars. Error messages name the variable but never echo its value. */
export function loadServerEnv(source: Record<string, string | undefined> = process.env): ServerEnv {
  const parsed = serverSchema.safeParse(source);
  if (!parsed.success) {
    const problems = parsed.error.issues.map((i) => `${i.path.join(".") || "env"}: ${i.message}`);
    throw new Error(`Invalid server environment:\n - ${problems.join("\n - ")}`);
  }
  return parsed.data;
}

let cached: ServerEnv | undefined;
export function serverEnv(): ServerEnv {
  return (cached ??= loadServerEnv());
}
