import { describe, expect, it } from "vitest";

import {
  assertTransition,
  boardTransitions,
  challengeTransitions,
  consentStageTransitions,
  consumableTransitions,
  documentTransitions,
  exportTransitions,
  instanceTransitions,
  jobTransitions,
  managementQuestionTransitions,
  meetingTransitions,
  memberTransitions,
  minutesTransitions,
  profileTransitions,
  proxyGrantTransitions,
  refreshFamilyTransitions,
  resignRequirementTransitions,
  reviewItemTransitions,
  rulesetTransitions,
  submissionTransitions,
  taskTransitions,
  transcriptTransitions,
  transitionAllowed,
  voteTransitions,
  wizardTransitions
} from "../../lib/domain/src/state-machines.js";

function expectExact<S extends string>(
  table: Readonly<Record<S, readonly S[]>>,
  expected: Readonly<Record<S, readonly S[]>>
): void {
  expect(table).toEqual(expected);
  for (const [current, allowed] of Object.entries(expected) as Array<[S, readonly S[]]>) {
    for (const candidate of Object.keys(expected) as S[]) {
      expect(transitionAllowed(table, current, candidate)).toBe(allowed.includes(candidate));
    }
  }
}

describe("frozen governance state machines", () => {
  it("requires the recoverable vote closing state and never reopens terminal votes", () => {
    expectExact(voteTransitions, {
      draft: ["open", "cancelled"],
      open: ["source_update_pending", "superseded", "closing", "cancelled"],
      source_update_pending: ["open", "superseded", "cancelled"],
      closing: ["closed"],
      closed: [],
      superseded: [],
      cancelled: []
    });
    expect(() => assertTransition(voteTransitions, "closing", "closed")).not.toThrow();
    expect(() => assertTransition(voteTransitions, "open", "closed")).toThrow("invalid transition");
  });

  it("keeps finalized minutes terminal and routes nonfinal correction back through review", () => {
    expectExact(minutesTransitions, {
      unpublished_draft: ["published_review", "cancelled"],
      published_review: ["published_review", "signature_ready", "cancelled"],
      signature_ready: ["published_review", "finalized", "cancelled"],
      finalized: [],
      cancelled: []
    });
  });

  it("keeps completed tasks terminal and rejects stale draft activation", () => {
    expectExact(taskTransitions, {
      draft: ["open", "cancelled", "superseded"],
      open: ["in_progress", "evidence_submitted", "cancelled"],
      in_progress: ["open", "evidence_submitted", "cancelled"],
      evidence_submitted: ["open", "completed", "cancelled"],
      completed: [],
      cancelled: [],
      superseded: []
    });
    expect(() => assertTransition(taskTransitions, "completed", "open")).toThrow(
      "invalid transition"
    );
  });

  it("models the frozen identity, content, meeting, and governance lifecycles exactly", () => {
    expectExact(instanceTransitions, {
      absent: ["active"],
      active: []
    });
    expectExact(memberTransitions, {
      invited: ["enrollment_pending", "removed"],
      enrollment_pending: ["pending_activation", "removed"],
      pending_activation: ["active", "removed"],
      active: ["suspended", "removed"],
      suspended: ["active", "removed"],
      removed: []
    });
    expectExact(boardTransitions, {
      active: ["archived"],
      archived: []
    });
    expectExact(consumableTransitions, {
      issued: ["consumed", "expired", "revoked"],
      consumed: [],
      expired: [],
      revoked: []
    });
    expectExact(refreshFamilyTransitions, {
      active: ["revoked", "compromised", "expired"],
      revoked: [],
      compromised: [],
      expired: []
    });
    expectExact(documentTransitions, {
      active: ["archived", "soft_deleted"],
      archived: ["soft_deleted"],
      soft_deleted: []
    });
    expectExact(submissionTransitions, {
      submitted: ["revision_requested", "approved_to_draft", "rejected"],
      revision_requested: ["resubmitted", "rejected"],
      resubmitted: ["revision_requested", "approved_to_draft", "rejected"],
      approved_to_draft: [],
      rejected: []
    });
    expectExact(managementQuestionTransitions, {
      pending: ["overdue", "answered"],
      overdue: ["answered"],
      answered: ["pending"]
    });
    expectExact(meetingTransitions, {
      draft: ["called", "cancelled"],
      called: ["called", "completed", "cancelled"],
      completed: [],
      cancelled: []
    });
    expectExact(transcriptTransitions, {
      unverified: ["secretary_verified"],
      secretary_verified: []
    });
    expectExact(challengeTransitions, {
      pending: ["accepted", "rejected"],
      accepted: [],
      rejected: []
    });
    expectExact(reviewItemTransitions, {
      pending: ["accepted", "rejected", "withdrawn"],
      accepted: [],
      rejected: [],
      withdrawn: []
    });
    expectExact(resignRequirementTransitions, {
      pending: ["resolved"],
      resolved: []
    });
    expectExact(proxyGrantTransitions, {
      active: ["revoked", "expired", "superseded"],
      revoked: [],
      expired: [],
      superseded: []
    });
    expectExact(consentStageTransitions, {
      active: ["replaced", "confirmed", "rejected", "expired", "cancelled"],
      replaced: [],
      confirmed: [],
      rejected: [],
      expired: [],
      cancelled: []
    });
    expectExact(wizardTransitions, {
      active: ["ready_to_confirm", "expired", "cancelled"],
      ready_to_confirm: ["posted", "expired", "cancelled"],
      posted: [],
      expired: [],
      cancelled: []
    });
    const profileExpected = {
      draft: ["active"],
      active: ["superseded"],
      superseded: []
    } as const;
    expectExact(profileTransitions, profileExpected);
    expectExact(rulesetTransitions, profileExpected);
    expectExact(exportTransitions, {
      staged: ["confirmed", "expired"],
      confirmed: ["queued", "expired"],
      queued: ["running", "failed", "expired"],
      running: ["succeeded", "failed"],
      succeeded: ["expired", "deleted"],
      failed: [],
      expired: ["deleted"],
      deleted: []
    });
    expectExact(jobTransitions, {
      queued: ["leased", "cancelled"],
      leased: ["succeeded", "retry", "dead", "cancelled"],
      retry: ["leased", "dead", "cancelled"],
      succeeded: [],
      dead: [],
      cancelled: []
    });
  });
});
