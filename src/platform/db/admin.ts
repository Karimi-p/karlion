import "server-only";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { serverEnv } from "@/platform/config/env";
import type { ApprovalStore, ClaimedApproval } from "@/platform/approvals/service";
import type { OutboxRow, OutboxStore } from "@/platform/events/dispatcher";
import type { ClaimOutcome, IdempotencyStore } from "@/platform/webhooks/inbound";

/**
 * Service-role client: bypasses RLS. Server-only (the `server-only` import fails the build if this
 * module is ever pulled into client code). Use it only inside route handlers/services that have
 * already authenticated and authorised the caller.
 */
let client: SupabaseClient | undefined;
export function adminClient(): SupabaseClient {
  const env = serverEnv();
  return (client ??= createClient(env.NEXT_PUBLIC_SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  }));
}

function unwrap<T>(res: { data: T | null; error: { message: string } | null }): T {
  if (res.error) throw new Error(res.error.message);
  return res.data as T;
}

export function outboxStore(db: SupabaseClient = adminClient()): OutboxStore {
  return {
    async claim(limit, leaseSeconds) {
      return unwrap<OutboxRow[]>(await db.rpc("claim_outbox_batch", { p_limit: limit, p_lease_seconds: leaseSeconds })) ?? [];
    },
    async markDelivered(id) {
      unwrap(await db.rpc("outbox_mark_delivered", { p_id: id }));
    },
    async markFailed(id, error, maxAttempts) {
      unwrap(await db.rpc("outbox_mark_failed", { p_id: id, p_error: error, p_max_attempts: maxAttempts }));
    },
  };
}

export function idempotencyStore(db: SupabaseClient = adminClient()): IdempotencyStore {
  return {
    async claim(scope, key, requestHash) {
      const rows = unwrap<{ outcome: ClaimOutcome; response: unknown; response_status: number | null }[]>(
        await db.rpc("idempotency_claim", { p_scope: scope, p_key: key, p_request_hash: requestHash }),
      );
      const row = rows?.[0];
      if (!row) throw new Error("idempotency_claim returned no row");
      return { outcome: row.outcome, response: row.response, responseStatus: row.response_status ?? undefined };
    },
    async complete(scope, key, response, status) {
      unwrap(await db.rpc("idempotency_complete", { p_scope: scope, p_key: key, p_response: response, p_status: status }));
    },
    async release(scope, key) {
      unwrap(await db.rpc("idempotency_release", { p_scope: scope, p_key: key }));
    },
  };
}

export function approvalStore(db: SupabaseClient = adminClient()): ApprovalStore {
  return {
    async claimExecution(approvalId) {
      const rows = unwrap<ClaimedApproval[]>(await db.rpc("claim_approval_execution", { p_id: approvalId }));
      const row = rows?.[0];
      if (!row) throw new Error("approval_not_executable");
      return row;
    },
    async completeExecution(approvalId, success, error) {
      unwrap(await db.rpc("complete_approval_execution", { p_id: approvalId, p_success: success, p_error: error ?? null }));
    },
  };
}
