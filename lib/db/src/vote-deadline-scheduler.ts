import type { PoolClient } from "pg";

import { Rfc3339UtcSchema, UuidV7Schema } from "@boardagent/contracts";

export interface ScheduleDueAutomaticVoteClosesInput {
  readonly organizationId: string;
  readonly boardId: string;
  readonly through: string;
  readonly newId: () => string;
  readonly limit?: number;
}

export interface ScheduledAutomaticVoteClose {
  readonly voteId: string;
  readonly jobId: string;
  readonly replayed: boolean;
}

interface VoteCandidateRow {
  readonly vote_id: string;
}

interface ScheduledVoteRow {
  readonly vote_id: string;
  readonly job_id: string;
  readonly replayed: boolean;
}

function boundedLimit(value: number | undefined): number {
  const limit = value ?? 100;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) {
    throw new RangeError("vote deadline batch limit must be an integer from 1 through 1000");
  }
  return limit;
}

/** Enqueue the single close kernel for exact due automatic-mode votes only. */
export async function scheduleDueAutomaticVoteClosesInTransaction(
  client: PoolClient,
  rawInput: ScheduleDueAutomaticVoteClosesInput
): Promise<readonly ScheduledAutomaticVoteClose[]> {
  const organizationId = UuidV7Schema.parse(rawInput.organizationId);
  const boardId = UuidV7Schema.parse(rawInput.boardId);
  const through = Rfc3339UtcSchema.parse(rawInput.through);
  const candidates = await client.query<VoteCandidateRow>(
    `select vote_id
       from public.boardagent_due_automatic_vote_candidates($1,$2,$3,$4)`,
    [organizationId, boardId, through, boundedLimit(rawInput.limit)]
  );
  const scheduled: ScheduledAutomaticVoteClose[] = [];
  for (const row of candidates.rows) {
    const voteId = UuidV7Schema.parse(row.vote_id);
    const proposedJobId = UuidV7Schema.parse(rawInput.newId());
    const result = await client.query<ScheduledVoteRow>(
      `select vote_id,job_id,replayed
         from public.boardagent_enqueue_due_automatic_vote_close($1,$2,$3,$4,$5)`,
      [proposedJobId, organizationId, boardId, voteId, through]
    );
    if (result.rows.length === 0) {
      // The kernel re-checked the exact vote under lock and found it not yet eligible
      // (package unbound, clock health missing, or closed meanwhile). Defer to a later scan.
      continue;
    }
    const stored = result.rows[0];
    if (!stored || result.rows.length !== 1 || stored.vote_id !== voteId) {
      throw new Error("locked automatic vote close candidate became unavailable");
    }
    scheduled.push({
      voteId,
      jobId: UuidV7Schema.parse(stored.job_id),
      replayed: stored.replayed
    });
  }
  return scheduled;
}
