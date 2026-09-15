import type { Pool } from "pg";
import { expect } from "vitest";
import {
  PgBoardAgentSurfaceService,
  type SurfacePrincipal
} from "../../artifacts/server/src/index.js";
import {
  TOOL_INPUT_SCHEMA_VERSION,
  sha256Hex,
  type JsonValue
} from "../../lib/contracts/src/index.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import {
  seedAdditionalAuthorizedActor,
  seedAuthorizedActor,
  testId,
  type AuthorizedActorFixture
} from "./authorized-actor.js";

type ActorName = "management" | "secretary" | "asker";
type Data = Readonly<Record<string, JsonValue>>;
export interface ManagementDocumentReference {
  readonly document_id: string;
  readonly version_id: string;
  readonly sha256: string;
}
const scopes = {
  management: ["documents:contribute", "documents:read", "governance:read", "management:question"],
  secretary: ["governance:read", "secretariat:admin"],
  asker: ["governance:read", "management:question"]
} as const;
const roles = {
  management: ["management"],
  secretary: ["member", "secretariat"],
  asker: ["member"]
} as const;
function object(value: JsonValue): Data {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new TypeError("management fixture result must be an object");
  return value as Data;
}
function required(data: Data, key: string): string {
  const value = data[key];
  if (typeof value !== "string" || !value) throw new Error(`management fixture ${key} is absent`);
  return value;
}
// Constrained synthetic session storage plus the actual resolver. This is not
// provider/browser authentication. The generic helper is private to this fixture.
async function resolvePrincipal(
  pool: Pool,
  actor: AuthorizedActorFixture,
  name: ActorName,
  ordinal: number
): Promise<SurfacePrincipal> {
  const sessionId = testId(480_010 + ordinal);
  await pool.query(
    `insert into auth_sessions(id,organization_id,opaque_session_sha256,member_id,client_id,
    state,exact_origin,expires_at,last_authenticated_at)
    values($1,$2,$3,$4,$5,'authenticated',$6,transaction_timestamp()+interval '10 minutes',transaction_timestamp())`,
    [
      sessionId,
      actor.organizationId,
      Buffer.alloc(32, 0xa0 + ordinal),
      actor.memberId,
      actor.clientId,
      "https://boardagent.test"
    ]
  );
  const linked = await pool.query(
    "update access_token_records set session_id=$2 where id=$1 and session_id is null returning id",
    [actor.accessTokenRecordId, sessionId]
  );
  expect(linked.rowCount).toBe(1);
  const live = await withRequestTransaction(
    pool,
    actor.context,
    async (client) => {
      const result = await client.query<{
        token_record_id: string;
        organization_id: string;
        member_id: string;
        internal_client_id: string;
        protocol_client_id: string;
        resource_uri: string;
        scope_set: string[];
        roles: string[];
        board_ids: string[];
      }>(
        "select token_record_id,organization_id,member_id,internal_client_id,protocol_client_id,resource_uri,scope_set,roles,board_ids from boardagent_resolve_access_token($1)",
        [actor.tokenJti]
      );
      expect(result.rows).toHaveLength(1);
      return result.rows[0]!;
    },
    { assumeRole: "boardagent_server" }
  );
  expect(live).toMatchObject({
    token_record_id: actor.accessTokenRecordId,
    organization_id: actor.organizationId,
    member_id: actor.memberId,
    internal_client_id: actor.clientId,
    resource_uri: "https://boardagent.test/mcp"
  });
  expect(live.protocol_client_id.length).toBeGreaterThan(0);
  expect([...live.scope_set].sort()).toEqual([...scopes[name]].sort());
  expect([...live.roles].sort()).toEqual([...roles[name]].sort());
  expect(live.board_ids).toEqual([actor.boardId]);
  return {
    organizationId: live.organization_id,
    memberId: live.member_id,
    serviceOrigin: "https://boardagent.test",
    clientId: live.internal_client_id,
    protocolClientId: live.protocol_client_id,
    accessTokenRecordId: live.token_record_id,
    tokenJti: actor.tokenJti,
    keyId: "test-oauth",
    scopes: live.scope_set,
    roles: live.roles,
    boardIds: live.board_ids
  };
}

export async function seedManagementProjectionFixture(pool: Pool) {
  const management = await seedAuthorizedActor(pool, {
    seatRole: "management",
    scopes: [...scopes.management]
  });
  const secretary = await seedAdditionalAuthorizedActor(pool, management, {
    idBase: 481_000,
    seatRole: "voting_member",
    isSecretary: true,
    scopes: [...scopes.secretary]
  });
  const asker = await seedAdditionalAuthorizedActor(pool, management, {
    idBase: 482_000,
    seatRole: "voting_member",
    scopes: [...scopes.asker]
  });
  const actors = { management, secretary, asker } as const;
  const principals = {
    management: await resolvePrincipal(pool, management, "management", 0),
    secretary: await resolvePrincipal(pool, secretary, "secretary", 1),
    asker: await resolvePrincipal(pool, asker, "asker", 2)
  } as const;
  let nextId = 483_000,
    sequence = 0,
    busy = false,
    failed = false;
  let submissionPhase = 0,
    questionPhase = 0,
    fourthSubmission = false,
    fourthQuestion = false;
  const commands: Array<
    Readonly<{ tool: string; actor: ActorName; reference: string | null; state: string | null }>
  > = [];
  const service = new PgBoardAgentSurfaceService(pool, {
    reads: {
      executeRead: async () => {
        throw new Error("read is outside management mutation fixture");
      },
      readResource: async () => {
        throw new Error("resource is outside management mutation fixture");
      }
    },
    transaction: { assumeRole: "boardagent_server" },
    newId: () => testId(nextId++)
  });
  const allowed = new Set([
    "create_document_version",
    "submit_document_to_secretariat",
    "request_management_revision",
    "reply_to_management_revision",
    "resubmit_management_materials",
    "approve_management_submission",
    "ask_management",
    "answer_management_question",
    "follow_up_management_question"
  ]);
  async function action(actor: ActorName, tool: string, input: Data) {
    if (!allowed.has(tool)) throw new Error("out-of-scope management fixture action");
    const result = await service.executeDirect(principals[actor], tool, {
      ...input,
      schema_version: TOOL_INPUT_SCHEMA_VERSION,
      idempotency_key: `management-projection-${++sequence}-${tool}`
    });
    expect(result.status).toBe("accepted");
    const data = object(result.data);
    if (data.replayed !== undefined) expect(data.replayed).toBe(false);
    commands.push(
      Object.freeze({
        tool,
        actor,
        reference: result.reference,
        state: typeof data.state === "string" ? data.state : null
      })
    );
    return { result, data };
  }
  async function once<T>(label: string, run: () => Promise<T>): Promise<T> {
    if (busy || failed)
      throw new Error(`management fixture cannot enter ${label} while busy or after failure`);
    busy = true;
    try {
      return await run();
    } catch (error) {
      failed = true;
      throw error;
    } finally {
      busy = false;
    }
  }
  const documentId = testId(480_100),
    submissionIds = [testId(480_200), testId(480_201), testId(480_202)] as const,
    questionIds = [testId(480_300), testId(480_301), testId(480_302)] as const;
  const originalText =
    '# Mining Exploration Co.\n\nSynthetic operating report: "Phase A" exploration; Δ samples await review.\n';
  const revisedText =
    '# Mining Exploration Co.\n\nSynthetic operating report: "Phase B" exploration; Δ figures now reconcile.\n';
  const revisionReason =
    'Please reconcile the "Phase A" assumptions.\nInclude the Δ source figures.';
  const replyText =
    'Management has reconciled the "Phase A" figures.\nThe next immutable source records Δ support.';
  const resubmissionReason = 'Appended the reconciled "Phase B" source.\nSynthetic evidence only.';
  async function contribute(
    body: string,
    current: string | null
  ): Promise<ManagementDocumentReference> {
    const { result } = await action("management", "create_document_version", {
      board_id: management.boardId,
      document_id: documentId,
      title: 'Mining Exploration Co. "Operating report" Δ',
      media_type: "text/markdown; charset=utf-8",
      schema_name: null,
      canonical_body: body,
      expected_current_version_id: current
    });
    if (typeof result.reference !== "string")
      throw new Error("normal management document version is absent");
    const reference = Object.freeze({
      document_id: documentId,
      version_id: result.reference,
      sha256: sha256Hex(body)
    });
    // Fixture metadata verification, not an authorization assertion or content read.
    const stored = await pool.query(
      `select document.current_version_id::text,encode(version.sha256,'hex') as sha256,
      version.byte_length::text from documents as document join document_versions as version on version.id=document.current_version_id where document.id=$1`,
      [documentId]
    );
    expect(stored.rows).toEqual([
      {
        current_version_id: reference.version_id,
        sha256: reference.sha256,
        byte_length: String(Buffer.byteLength(body))
      }
    ]);
    return reference;
  }
  const firstDocumentReference = await contribute(originalText, null);
  let currentDocumentReference = firstDocumentReference,
    currentSubmissionVersion = "",
    requestId: string | null = null,
    resultingDraftId: string | null = null;
  async function submit(id: string, purpose: string) {
    const { result, data } = await action("management", "submit_document_to_secretariat", {
      board_id: management.boardId,
      submission_id: id,
      document_references: [{ ...currentDocumentReference }],
      purpose
    });
    expect(result.reference).toBe(id);
    expect(data).toMatchObject({ state: "submitted", version: 1 });
    const stored = await pool.query<{ current_version_id: string }>(
      "select current_version_id::text from management_submission_threads where id=$1",
      [id]
    );
    expect(stored.rows).toHaveLength(1);
    if (typeof stored.rows[0]?.current_version_id !== "string")
      throw new Error("normal submission current version is absent");
    if (data.version_id !== undefined)
      expect(data.version_id).toBe(stored.rows[0].current_version_id);
    return stored.rows[0].current_version_id;
  }
  for (let index = 0; index < submissionIds.length; index++) {
    const version = await submit(
      submissionIds[index]!,
      `Synthetic Mining Exploration Co. report ${index + 1}: "Review" Δ`
    );
    if (index === 0) currentSubmissionVersion = version;
  }
  async function ask(id: string, suffix: string) {
    const { data } = await action("asker", "ask_management", {
      board_id: management.boardId,
      question_id: id,
      owner_member_id: management.memberId,
      due_at: "2099-09-20T12:00:00Z",
      question: `Which synthetic exploration assumptions support "${suffix}"?\nPlease explain the Δ variance.`,
      citations: []
    });
    expect(data).toMatchObject({ state: "pending", turn_ordinal: 1 });
  }
  for (let index = 0; index < questionIds.length; index++)
    await ask(questionIds[index]!, `report ${index + 1}`);
  expect(commands).toHaveLength(7);
  return {
    actors,
    principals,
    boardId: management.boardId,
    documentId,
    firstDocumentReference,
    submissionIds,
    questionIds,
    absentSubmissionId: testId(480_299),
    fourthSubmissionId: testId(480_203),
    fourthQuestionId: testId(480_303),
    originalText,
    revisedText,
    revisionReason,
    replyText,
    resubmissionReason,
    get commands() {
      return Object.freeze([...commands]);
    },
    get currentDocumentReference() {
      return currentDocumentReference;
    },
    get currentSubmissionVersion() {
      return currentSubmissionVersion;
    },
    get requestId() {
      return requestId;
    },
    get resultingDraftId() {
      return resultingDraftId;
    },
    requestMainRevision: () =>
      once("requestMainRevision", async () => {
        if (submissionPhase !== 0)
          throw new Error("main submission is not ready for its revision request");
        const { data } = await action("secretary", "request_management_revision", {
          submission_id: submissionIds[0],
          reason: revisionReason
        });
        expect(data.state).toBe("revision_requested");
        requestId = required(data, "revision_request_id");
        submissionPhase = 1;
      }),
    replyToMainRevision: () =>
      once("replyToMainRevision", async () => {
        if (submissionPhase !== 1 || requestId === null)
          throw new Error("main revision request is not available");
        await action("management", "reply_to_management_revision", {
          submission_id: submissionIds[0],
          revision_request_id: requestId,
          reply: replyText
        });
        submissionPhase = 2;
      }),
    reviseSourceAndResubmitMain: () =>
      once("reviseSourceAndResubmitMain", async () => {
        if (submissionPhase !== 2) throw new Error("main reply must precede resubmission");
        currentDocumentReference = await contribute(
          revisedText,
          currentDocumentReference.version_id
        );
        const { data } = await action("management", "resubmit_management_materials", {
          submission_id: submissionIds[0],
          document_references: [{ ...currentDocumentReference }],
          reason: resubmissionReason
        });
        expect(data).toMatchObject({ state: "resubmitted", version: 2 });
        currentSubmissionVersion = required(data, "version_id");
        submissionPhase = 3;
      }),
    approveMain: () =>
      once("approveMain", async () => {
        if (submissionPhase !== 3) throw new Error("main resubmission must precede approval");
        const { data } = await action("secretary", "approve_management_submission", {
          submission_id: submissionIds[0],
          version_id: currentSubmissionVersion
        });
        expect(data.state).toBe("approved_to_draft");
        resultingDraftId = required(data, "resulting_draft_id");
        submissionPhase = 4;
      }),
    answerFirstQuestion: () =>
      once("answerFirstQuestion", async () => {
        if (questionPhase !== 0)
          throw new Error("first question is not awaiting its initial answer");
        const { data } = await action("management", "answer_management_question", {
          question_id: questionIds[0],
          answer: 'The "Phase A" variance is synthetic.\nΔ source figures are reconciled.'
        });
        expect(data).toMatchObject({ state: "answered", turn_ordinal: 2 });
        questionPhase = 1;
      }),
    followUpFirstQuestion: () =>
      once("followUpFirstQuestion", async () => {
        if (questionPhase !== 1)
          throw new Error("first question must be answered before follow-up");
        const { data } = await action("asker", "follow_up_management_question", {
          question_id: questionIds[0],
          follow_up: 'Please quantify the "Phase B" variance.\nRetain the Δ qualification.',
          due_at: "2099-09-21T12:00:00Z"
        });
        expect(data).toMatchObject({ state: "pending", turn_ordinal: 3 });
        questionPhase = 2;
      }),
    answerFirstQuestionAgain: () =>
      once("answerFirstQuestionAgain", async () => {
        if (questionPhase !== 2)
          throw new Error("first question must be reopened before its second answer");
        const { data } = await action("management", "answer_management_question", {
          question_id: questionIds[0],
          answer:
            'The "Phase B" variance is zero in this synthetic example.\nΔ evidence remains illustrative.'
        });
        expect(data).toMatchObject({ state: "answered", turn_ordinal: 4 });
        questionPhase = 3;
      }),
    appendFourthSubmission: () =>
      once("appendFourthSubmission", async () => {
        if (fourthSubmission) throw new Error("fourth submission already exists");
        await submit(testId(480_203), 'Synthetic fourth submission: "Newcomer" Δ');
        fourthSubmission = true;
      }),
    appendFourthQuestion: () =>
      once("appendFourthQuestion", async () => {
        if (fourthQuestion) throw new Error("fourth question already exists");
        await ask(testId(480_303), "fourth newcomer");
        fourthQuestion = true;
      })
  };
}
export type ManagementProjectionFixture = Awaited<
  ReturnType<typeof seedManagementProjectionFixture>
>;
