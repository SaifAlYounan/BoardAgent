import { createHash } from "node:crypto";
import type { PoolClient } from "pg";
import {
  listAdmittedManagementQuestionsInTransaction,
  type ListManagementQuestionsInput,
  type ListManagementQuestionsResult,
  type ManagementQuestionListProjectionObservation
} from "@boardagent/db";
import {
  currentResponseAllocationOwner,
  ResponseAllocationUnavailable,
  responseAllocationPlan,
  type ListProjectionScalars,
  type ResponseAllocationPlan
} from "./response-allocation.js";
function scalar(value: string): bigint {
  if (typeof value !== "string") throw new TypeError("question list scalar is invalid");
  if (value.length > 24) throw new ResponseAllocationUnavailable();
  if (!/^(0|[1-9][0-9]*)$/u.test(value)) throw new TypeError("question list scalar is invalid");
  return BigInt(value);
}
export function questionListProjectionCost(
  metadata: Pick<
    ManagementQuestionListProjectionObservation,
    "row_count" | "scalar_utf8" | "json_utf8" | "json_properties" | "json_containers"
  >
): ListProjectionScalars {
  const r = scalar(metadata.row_count),
    s = scalar(metadata.scalar_utf8),
    n = scalar(metadata.json_utf8),
    p = scalar(metadata.json_properties),
    o = scalar(metadata.json_containers);
  if (r > 501n) throw new TypeError("question list count is invalid");
  // The aggregate/header, sliced result and conservatively parsed page can be
  // retained together. Pay both complete item/owner graphs, unlike plain pages.
  // The original fresh total_visible signed-bigint text gets20 scalar bytes.
  return {
    jsonUpperBytes: (166n + 224n * r + 6n * s + n).toString(),
    propertyCount: (33n + 22n * r + 2n * p).toString(),
    objectOrArrayCount: (12n + 2n * r + 2n * o).toString()
  };
}
export function questionListProjectionPlan(
  input: ListManagementQuestionsInput,
  metadata: ManagementQuestionListProjectionObservation
): ResponseAllocationPlan {
  return responseAllocationPlan({
    kind: "management_read_projection",
    representation: "tool",
    canonicalBytes: 0,
    sourceId: input.boardId,
    sourceVersion: `questions:${input.limit ?? 50}`,
    sha256: createHash("sha256")
      .update(JSON.stringify([input, metadata]))
      .digest("hex"),
    listProjection: questionListProjectionCost(metadata)
  });
}
export async function loadAdmittedQuestionList(
  client: PoolClient,
  input: ListManagementQuestionsInput
): Promise<ListManagementQuestionsResult> {
  const owner = currentResponseAllocationOwner();
  if (!owner) throw new TypeError("question list requires a native request owner");
  owner.assertLive();
  return listAdmittedManagementQuestionsInTransaction(client, input, {
    assertLive: () => owner.assertLive(),
    reserve: (metadata) => {
      owner.reserve(questionListProjectionPlan(input, metadata));
    },
    unavailable: () => {
      throw new ResponseAllocationUnavailable();
    }
  });
}
