import type { PoolClient } from "pg";

import { Rfc3339UtcSchema, UuidV7Schema } from "@boardagent/contracts";

export interface MarkOverdueManagementQuestionsInput {
  readonly limit?: number;
}

export interface OverdueManagementQuestionProjection {
  readonly questionId: string;
  readonly boardId: string;
  readonly rowVersion: bigint;
}

interface OverdueRow {
  readonly board_id: string;
  readonly question_id: string;
  readonly row_version: string;
}

function boundedLimit(value: number | undefined): number {
  const limit = value ?? 100;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) {
    throw new RangeError("question overdue batch limit must be an integer from 1 through 1000");
  }
  return limit;
}

export async function markDueManagementQuestionsOverdueInTransaction(
  client: PoolClient,
  input: MarkOverdueManagementQuestionsInput = {}
): Promise<readonly OverdueManagementQuestionProjection[]> {
  const limit = boundedLimit(input.limit);
  const result = await client.query<OverdueRow>(
    `select question_id,board_id,row_version::text
       from boardagent_mark_due_questions_overdue($1)`,
    [limit]
  );
  return result.rows.map((row) => {
    const questionId = UuidV7Schema.parse(row.question_id);
    const boardId = UuidV7Schema.parse(row.board_id);
    const rowVersion = BigInt(row.row_version);
    if (rowVersion < 2n) throw new Error("overdue question row version is invalid");
    return { questionId, boardId, rowVersion };
  });
}

export async function markDueBoardQuestionsOverdueInTransaction(
  client: PoolClient,
  input: {
    readonly organizationId: string;
    readonly boardId: string;
    readonly through: string;
    readonly limit?: number;
  }
): Promise<readonly OverdueManagementQuestionProjection[]> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const boardId = UuidV7Schema.parse(input.boardId);
  const through = Rfc3339UtcSchema.parse(input.through);
  const limit = boundedLimit(input.limit);
  const result = await client.query<OverdueRow>(
    `select question_id,board_id,row_version::text
       from boardagent_mark_board_questions_overdue($1,$2,$3,$4)`,
    [organizationId, boardId, through, limit]
  );
  return result.rows.map((row) => {
    const questionId = UuidV7Schema.parse(row.question_id);
    const resultBoardId = UuidV7Schema.parse(row.board_id);
    const rowVersion = BigInt(row.row_version);
    if (resultBoardId !== boardId || rowVersion < 2n) {
      throw new Error("board-bound overdue question projection is invalid");
    }
    return { questionId, boardId: resultBoardId, rowVersion };
  });
}
