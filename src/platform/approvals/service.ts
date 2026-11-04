export const ACTION_TYPES = [
  "financial_transaction",
  "production_deployment",
  "destructive_operation",
  "external_commitment",
] as const;
export type ActionType = (typeof ACTION_TYPES)[number];

export type ApprovalPolicy = Partial<Record<string, { required?: boolean }>>;

/** Fail closed: anything not explicitly marked `required: false` needs approval. */
export function requiresApproval(policy: ApprovalPolicy | null | undefined, action: string): boolean {
  return policy?.[action]?.required !== false;
}

export interface ClaimedApproval {
  approval_id: string;
  organization_id: string;
  action_type: ActionType;
  payload: unknown;
  payload_hash: string;
}

export interface ApprovalStore {
  claimExecution(approvalId: string): Promise<ClaimedApproval>;
  completeExecution(approvalId: string, success: boolean, error?: string): Promise<void>;
}

/**
 * Runs an approved action exactly once. The database only releases the stored payload for an
 * approved, unexpired request and flips it to 'executing' atomically, so a second call throws
 * before the executor runs. The executor receives the payload as approved, not caller-supplied data.
 */
export async function executeApproved<T>(
  store: ApprovalStore,
  approvalId: string,
  executor: (claim: ClaimedApproval) => Promise<T>,
): Promise<T> {
  const claim = await store.claimExecution(approvalId);
  try {
    const result = await executor(claim);
    await store.completeExecution(approvalId, true);
    return result;
  } catch (err) {
    await store.completeExecution(approvalId, false, err instanceof Error ? err.message : "execution failed");
    throw err;
  }
}
