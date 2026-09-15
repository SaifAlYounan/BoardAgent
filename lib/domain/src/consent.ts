import { safeHashEqual, sha256Hex } from "@boardagent/contracts";

export interface ActionStage {
  readonly status: "active" | "replaced" | "confirmed" | "rejected" | "expired" | "cancelled";
  readonly actionType: string;
  readonly targetId: string;
  readonly actorMemberId: string;
  readonly canonicalHash: string;
  readonly requestHash: string;
  readonly protectedStateHash: string;
  readonly confirmationCodeHash: string;
  readonly expiresAtMs: number;
}

export interface ConfirmationAttempt {
  readonly action: "accept" | "decline" | "cancel";
  readonly approve: boolean;
  readonly confirmationCode: string;
  readonly protectedState: string;
  readonly requestHash: string;
  readonly canonicalHash: string;
  readonly nowMs: number;
}

export type ConfirmationResult =
  | { readonly accepted: true }
  | {
      readonly accepted: false;
      readonly reason:
        | "stage_not_active"
        | "expired"
        | "declined"
        | "request_mismatch"
        | "state_mismatch"
        | "canonical_stale"
        | "code_mismatch";
    };

export function verifyConfirmation(
  stage: ActionStage,
  attempt: ConfirmationAttempt
): ConfirmationResult {
  if (!Number.isFinite(stage.expiresAtMs) || !Number.isFinite(attempt.nowMs)) {
    throw new RangeError("consent expiry and clock must be finite timestamps");
  }
  if (stage.status !== "active") return { accepted: false, reason: "stage_not_active" };
  if (attempt.nowMs >= stage.expiresAtMs) return { accepted: false, reason: "expired" };
  if (attempt.action !== "accept" || !attempt.approve)
    return { accepted: false, reason: "declined" };
  if (!safeHashEqual(stage.requestHash, attempt.requestHash))
    return { accepted: false, reason: "request_mismatch" };
  if (!safeHashEqual(stage.protectedStateHash, sha256Hex(attempt.protectedState))) {
    return { accepted: false, reason: "state_mismatch" };
  }
  if (!safeHashEqual(stage.canonicalHash, attempt.canonicalHash)) {
    return { accepted: false, reason: "canonical_stale" };
  }
  if (!safeHashEqual(stage.confirmationCodeHash, sha256Hex(attempt.confirmationCode))) {
    return { accepted: false, reason: "code_mismatch" };
  }
  return { accepted: true };
}
