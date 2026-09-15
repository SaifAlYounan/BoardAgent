import { createHash } from "node:crypto";
import type { PoolClient } from "pg";
import {
  getAdmittedManagementQuestionInTransaction,
  type ManagementQuestionProjectionMetadata,
  type ManagementQuestionView
} from "@boardagent/db";
import {
  currentResponseAllocationOwner,
  ResponseAllocationUnavailable,
  responseAllocationPlan,
  type ListProjectionScalars,
  type ResponseAllocationPlan
} from "./response-allocation.js";

function scalar(value: string): bigint {
  if (typeof value !== "string") throw new TypeError("question projection scalar is invalid");
  if (value.length > 24) throw new ResponseAllocationUnavailable();
  if (!/^(0|[1-9][0-9]*)$/u.test(value))
    throw new TypeError("question projection scalar is invalid");
  return BigInt(value);
}

export function questionProjectionCost(
  metadata: ManagementQuestionProjectionMetadata
): ListProjectionScalars {
  const turns = scalar(metadata.projected_turn_count);
  const deliveries = scalar(metadata.delivery_count);
  const links = scalar(metadata.link_count);
  const flat = scalar(metadata.scalar_utf8);
  const json = scalar(metadata.json_utf8);
  const properties = scalar(metadata.json_properties);
  const containers = scalar(metadata.json_containers);
  // Preserve the independent answer count and the old safe-number count contract.
  // Unsafe persisted counts are refused before the final JSON/driver conversion.
  for (const value of [metadata.turn_count, metadata.answer_count])
    if (scalar(value) > BigInt(Number.MAX_SAFE_INTEGER)) throw new ResponseAllocationUnavailable();
  // Exact field sets: 15 root, 10 turn, 8 notice and 7 decision-link fields.
  // Each object allows 2 + sum(key.length + 10), each child adds two array
  // delimiter bytes. Original JSONB has ALREADY been serialized: N enters once.
  // Flat scalar UTF-8 can need six JSON escape bytes per byte. Arbitrary JSONB
  // properties/containers are counted exactly in PostgreSQL, not inferred from N.
  const j = 303n + 204n * turns + 170n * deliveries + 188n * links + 6n * flat + json;
  const p = 15n + 10n * turns + 8n * deliveries + 7n * links + properties + 23n;
  const o = 4n + turns + deliveries + links + containers + 5n;
  return {
    jsonUpperBytes: j.toString(),
    propertyCount: p.toString(),
    objectOrArrayCount: o.toString()
  };
}

export function questionProjectionPlan(
  metadata: ManagementQuestionProjectionMetadata,
  representation: "tool" | "resource"
): ResponseAllocationPlan {
  if (scalar(metadata.row_version) < 1n) throw new TypeError("question row version is invalid");
  // This digest binds the private authorized observation identity, not a public
  // content commitment. Mutable children may change only under the fresh gate.
  const identity = createHash("sha256")
    .update(
      JSON.stringify([
        metadata.question_id,
        metadata.board_id,
        metadata.row_version,
        metadata.current_turn_id
      ])
    )
    .digest("hex");
  return responseAllocationPlan({
    kind: "question_projection",
    representation,
    sourceId: metadata.question_id,
    sourceVersion: metadata.row_version,
    sha256: identity,
    canonicalBytes: 0,
    listProjection: questionProjectionCost(metadata)
  });
}

export async function loadAdmittedManagementQuestion(
  client: PoolClient,
  questionId: string,
  representation: "tool" | "resource",
  boardId?: string
): Promise<ManagementQuestionView | null> {
  const owner = currentResponseAllocationOwner();
  if (!owner) throw new TypeError("question projection requires a native request owner");
  owner.assertLive();
  return getAdmittedManagementQuestionInTransaction(
    client,
    questionId,
    {
      assertLive: () => owner.assertLive(),
      reserve: (metadata) => {
        owner.reserve(questionProjectionPlan(metadata, representation));
      },
      unavailable: () => {
        throw new ResponseAllocationUnavailable();
      }
    },
    boardId
  );
}
