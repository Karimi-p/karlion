import { describe, expect, it, vi } from "vitest";
import { executeApproved, requiresApproval, type ApprovalStore, type ClaimedApproval } from "./service";

const claim: ClaimedApproval = { approval_id: "a1", organization_id: "o", action_type: "financial_transaction", payload: { amount_minor: 100 }, payload_hash: "h" };

function store(over: Partial<ApprovalStore> = {}): ApprovalStore {
  return { claimExecution: vi.fn(async () => claim), completeExecution: vi.fn(async () => undefined), ...over };
}

describe("requiresApproval", () => {
  it("requires approval by default and for unknown actions (fail closed)", () => {
    expect(requiresApproval(undefined, "financial_transaction")).toBe(true);
    expect(requiresApproval({}, "something_new")).toBe(true);
    expect(requiresApproval({ financial_transaction: {} }, "financial_transaction")).toBe(true);
  });
  it("only skips approval when explicitly disabled", () => {
    expect(requiresApproval({ external_commitment: { required: false } }, "external_commitment")).toBe(false);
    expect(requiresApproval({ external_commitment: { required: true } }, "external_commitment")).toBe(true);
  });
});

describe("executeApproved", () => {
  it("executes the claimed payload and marks success", async () => {
    const s = store();
    const run = vi.fn(async (c: ClaimedApproval) => c.payload);
    await expect(executeApproved(s, "a1", run)).resolves.toEqual({ amount_minor: 100 });
    expect(s.completeExecution).toHaveBeenCalledWith("a1", true);
  });

  it("marks failure and rethrows when the executor fails", async () => {
    const s = store();
    await expect(executeApproved(s, "a1", async () => { throw new Error("bank down"); })).rejects.toThrow("bank down");
    expect(s.completeExecution).toHaveBeenCalledWith("a1", false, "bank down");
  });

  it("never runs the executor when the claim is refused (not approved / already executed / expired)", async () => {
    const s = store({ claimExecution: vi.fn(async () => { throw new Error("approval_not_executable"); }) });
    const run = vi.fn();
    await expect(executeApproved(s, "a1", run)).rejects.toThrow("approval_not_executable");
    expect(run).not.toHaveBeenCalled();
    expect(s.completeExecution).not.toHaveBeenCalled();
  });
});
