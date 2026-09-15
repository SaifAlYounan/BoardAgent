import { describe, expect, it } from "vitest";

import { TypedJobEnvelopeSchema } from "../../lib/db/src/jobs.js";
import { testId } from "../helpers/authorized-actor.js";

const ORGANIZATION_ID = testId(36_001);
const BOARD_ID = testId(36_002);
const VOTE_ID = testId(36_003);

describe("TH-36 forged job payload and cross-board binding", () => {
  it("accepts only a typed envelope whose parameter, subject, and board agree", () => {
    const valid = {
      schemaVersion: "boardagent.job.automatic_vote_close.v1",
      jobType: "automatic_vote_close",
      organizationId: ORGANIZATION_ID,
      boardId: BOARD_ID,
      subjectType: "vote",
      subjectId: VOTE_ID,
      parameters: { voteId: VOTE_ID }
    } as const;
    expect(TypedJobEnvelopeSchema.parse(valid)).toEqual(valid);

    expect(
      TypedJobEnvelopeSchema.safeParse({ ...valid, jobType: "forged_worker_call" }).success
    ).toBe(false);
    expect(
      TypedJobEnvelopeSchema.safeParse({
        ...valid,
        subjectId: testId(36_004)
      }).success
    ).toBe(false);
    expect(TypedJobEnvelopeSchema.safeParse({ ...valid, boardId: null }).success).toBe(false);
    expect(
      TypedJobEnvelopeSchema.safeParse({ ...valid, parameters: { voteId: testId(36_005) } }).success
    ).toBe(false);
    expect(TypedJobEnvelopeSchema.safeParse({ ...valid, leaseOwner: "attacker" }).success).toBe(
      false
    );
  });
});
