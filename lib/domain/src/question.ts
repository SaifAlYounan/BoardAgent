import {
  canonicalJson,
  canonicalSha256,
  canonicalText,
  GovernanceCitationSchema,
  Rfc3339UtcSchema,
  sha256Hex,
  UuidV7Schema
} from "@boardagent/contracts";

export interface ManagementQuestionCitation {
  readonly sourceDocumentVersionId: string;
  readonly sourceDocumentSha256: string;
  readonly clause: string;
  readonly locator: string;
}

export type QuestionVisibilityGrant =
  | { readonly granteeType: "member"; readonly memberId: string }
  | {
      readonly granteeType: "seat_role";
      readonly seatRole: "voting_member" | "management" | "observer";
    };

export interface ManagementQuestionInput {
  readonly questionId: string;
  readonly boardId: string;
  readonly question: string;
  readonly assignedOwnerIds: readonly string[];
  readonly dueAt: string;
  readonly citations: readonly ManagementQuestionCitation[];
  readonly visibility: readonly QuestionVisibilityGrant[];
}

export interface PreparedManagementQuestion {
  readonly questionId: string;
  readonly boardId: string;
  readonly question: string;
  readonly assignedOwnerIds: readonly string[];
  readonly dueAt: string;
  readonly citations: readonly ManagementQuestionCitation[];
  readonly visibility: readonly QuestionVisibilityGrant[];
  readonly aclPolicy: Readonly<{
    schemaVersion: "boardagent.question-acl.v1";
    grants: readonly QuestionVisibilityGrant[];
  }>;
  readonly textSha256: string;
  readonly canonicalPayload: Uint8Array;
  readonly requestSha256: string;
}

function normalizedCitations(
  citations: readonly ManagementQuestionCitation[]
): readonly ManagementQuestionCitation[] {
  if (citations.length > 64) throw new RangeError("question citations cannot exceed 64 entries");
  return citations.map((citation) =>
    GovernanceCitationSchema.parse(citation)
  ) as readonly ManagementQuestionCitation[];
}

function normalizedVisibility(
  visibility: readonly QuestionVisibilityGrant[]
): readonly QuestionVisibilityGrant[] {
  const seatRoles = new Set(["voting_member", "management", "observer"]);
  if (visibility.length < 1 || visibility.length > 1003) {
    throw new RangeError("question visibility must contain 1 through 1003 grants");
  }
  const normalized = new Map<string, QuestionVisibilityGrant>();
  for (const grant of visibility) {
    if (grant.granteeType === "member") {
      const memberId = UuidV7Schema.parse(grant.memberId);
      normalized.set(`member:${memberId}`, { granteeType: "member", memberId });
      continue;
    }
    if (grant.granteeType !== "seat_role" || !seatRoles.has(grant.seatRole)) {
      throw new TypeError("question visibility grant is invalid");
    }
    normalized.set(`seat_role:${grant.seatRole}`, {
      granteeType: "seat_role",
      seatRole: grant.seatRole
    });
  }
  return [...normalized.entries()]
    .toSorted(([left], [right]) => left.localeCompare(right))
    .map(([, grant]) => grant);
}

function normalizedOwners(ownerIds: readonly string[]): readonly string[] {
  if (ownerIds.length < 1 || ownerIds.length > 1000) {
    throw new RangeError("assigned owner IDs must contain 1 through 1000 entries");
  }
  return [...new Set(ownerIds.map((ownerId) => UuidV7Schema.parse(ownerId)))].toSorted();
}

function canonicalNonblank(value: string, label: string): string {
  const canonical = canonicalText(value);
  if (canonical.length > 1_048_576) throw new RangeError(`${label} exceeds 1 MiB`);
  if (canonical.trim().length === 0) throw new TypeError(`${label} must be nonblank`);
  return canonical;
}

export function prepareManagementQuestion(
  input: ManagementQuestionInput
): PreparedManagementQuestion {
  const questionId = UuidV7Schema.parse(input.questionId);
  const boardId = UuidV7Schema.parse(input.boardId);
  const question = canonicalNonblank(input.question, "management question");
  const assignedOwnerIds = normalizedOwners(input.assignedOwnerIds);
  const dueAt = Rfc3339UtcSchema.parse(input.dueAt);
  const citations = normalizedCitations(input.citations);
  const visibility = normalizedVisibility(input.visibility);
  const aclPolicy = {
    schemaVersion: "boardagent.question-acl.v1" as const,
    grants: visibility
  };
  const payload = {
    schemaVersion: "boardagent.management-question.v1" as const,
    questionId,
    boardId,
    question,
    assignedOwnerIds,
    dueAt,
    citations,
    aclPolicy
  };
  const canonicalPayload = new TextEncoder().encode(canonicalJson(payload));
  return {
    questionId,
    boardId,
    question,
    assignedOwnerIds,
    dueAt,
    citations,
    visibility,
    aclPolicy,
    textSha256: sha256Hex(question),
    canonicalPayload,
    requestSha256: canonicalSha256(payload)
  };
}

interface ManagementQuestionTurnBaseInput {
  readonly questionId: string;
  readonly text: string;
  readonly citations: readonly ManagementQuestionCitation[];
}

export type ManagementQuestionTurnInput =
  | (ManagementQuestionTurnBaseInput & {
      readonly turnKind: "answer";
      readonly dueAt?: never;
    })
  | (ManagementQuestionTurnBaseInput & {
      readonly turnKind: "follow_up";
      readonly dueAt: string;
    });

export interface PreparedManagementQuestionTurn {
  readonly questionId: string;
  readonly turnKind: "answer" | "follow_up";
  readonly text: string;
  readonly citations: readonly ManagementQuestionCitation[];
  readonly dueAt: string | null;
  readonly textSha256: string;
  readonly canonicalPayload: Uint8Array;
  readonly requestSha256: string;
}

export function prepareManagementQuestionTurn(
  input: ManagementQuestionTurnInput
): PreparedManagementQuestionTurn {
  const questionId = UuidV7Schema.parse(input.questionId);
  const text = canonicalNonblank(input.text, "management question turn");
  const citations = normalizedCitations(input.citations);
  const dueAt = input.turnKind === "follow_up" ? Rfc3339UtcSchema.parse(input.dueAt) : null;
  const payload = {
    schemaVersion: "boardagent.management-question-turn.v1" as const,
    questionId,
    turnKind: input.turnKind,
    text,
    citations,
    dueAt
  };
  return {
    questionId,
    turnKind: input.turnKind,
    text,
    citations,
    dueAt,
    textSha256: sha256Hex(text),
    canonicalPayload: new TextEncoder().encode(canonicalJson(payload)),
    requestSha256: canonicalSha256(payload)
  };
}
