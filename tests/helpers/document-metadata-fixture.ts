import type { Pool } from "pg";
import {
  PgBoardAgentSurfaceService,
  type BoardAgentSurfaceService,
  type SurfacePrincipal
} from "../../artifacts/server/src/index.js";
import { canonicalJson, TOOL_INPUT_SCHEMA_VERSION } from "../../lib/contracts/src/index.js";
import { seedAuthorizedActor, testId, type AuthorizedActorFixture } from "./authorized-actor.js";

export interface DocumentMetadataFixture {
  readonly actor: AuthorizedActorFixture;
  readonly principal: SurfacePrincipal;
  readonly documentAId: string;
  readonly documentBId: string;
  readonly rejectedDocumentId: string;
  readonly absentDocumentId: string;
  readonly absentVersionId: string;
  readonly absentAttemptId: string;
  readonly firstVersionId: string;
  readonly secondVersionId: string;
  readonly documentBVersionId: string;
  readonly firstAcceptedAttemptId: string;
  readonly acceptedAttemptId: string;
  readonly rejectedAttemptId: string;
  readonly attempts: readonly Readonly<{
    name: string;
    outcome: "accepted" | "rejected";
    reference: string | null;
  }>[];
  growDocumentA(): Promise<string>;
  createThirdDocument(): Promise<{ documentId: string; versionId: string }>;
}

// Normal contribution-only service, following the existing exact document test
// setup. Neither resource content nor a body/resource diagnostic is fetched.
const unavailableReads: Pick<BoardAgentSurfaceService, "executeRead" | "readResource"> = {
  executeRead: async () => {
    throw new Error("read is outside document contribution fixture");
  },
  readResource: async () => {
    throw new Error("resource read is outside document contribution fixture");
  }
};
export async function seedDocumentMetadataFixture(pool: Pool): Promise<DocumentMetadataFixture> {
  const actor = await seedAuthorizedActor(pool, {
    seatRole: "voting_member",
    isSecretary: true,
    scopes: ["documents:contribute", "documents:read"]
  });
  const principal: SurfacePrincipal = {
    organizationId: actor.organizationId,
    memberId: actor.memberId,
    serviceOrigin: "https://boardagent.test",
    clientId: actor.clientId,
    protocolClientId: "https://secretary-agent.test/client.json",
    accessTokenRecordId: actor.accessTokenRecordId,
    tokenJti: actor.tokenJti,
    keyId: "test-oauth",
    scopes: ["documents:contribute", "documents:read"],
    roles: ["member", "secretariat"],
    boardIds: [actor.boardId]
  };
  let nextId = 286_500;
  const service = new PgBoardAgentSurfaceService(pool, {
    reads: unavailableReads,
    transaction: { assumeRole: "boardagent_server" },
    newId: () => testId(nextId++)
  });
  const documentAId = testId(286_010),
    documentBId = testId(286_020),
    rejectedDocumentId = testId(286_030);
  const attempts: Array<
    Readonly<{ name: string; outcome: "accepted" | "rejected"; reference: string | null }>
  > = [];
  const title = 'Mining Exploration Co. "charter" Δ';
  const firstBody =
    "# Mining Exploration Co.\n\nSynthetic board charter. The secretary records minutes; three directors review exploration decisions.\n";
  const pack = (phase: string) =>
    canonicalJson({
      schemaVersion: "boardagent.board-pack.v1",
      title: "Mining Exploration Co. synthetic board charter",
      sections: [
        {
          heading: "Roles",
          body: "One secretary and three board members; synthetic documents only."
        },
        { heading: "Exploration", body: phase }
      ]
    });
  const contribute = async (
    name: string,
    documentId: string,
    documentTitle: string,
    body: string,
    current: string | null,
    typed: boolean
  ): Promise<string> => {
    const result = await service.executeDirect(principal, "create_document_version", {
      schema_version: TOOL_INPUT_SCHEMA_VERSION,
      board_id: actor.boardId,
      document_id: documentId,
      title: documentTitle,
      media_type: typed ? "application/json" : "text/markdown; charset=utf-8",
      schema_name: typed ? "boardagent.board-pack.v1" : null,
      canonical_body: body,
      expected_current_version_id: current,
      idempotency_key: `document-metadata-fixture-${name}`
    });
    if (result.status !== "accepted" || typeof result.reference !== "string")
      throw new Error(`normal document contribution failed: ${name}`);
    attempts.push(Object.freeze({ name, outcome: "accepted", reference: result.reference }));
    const state = await pool.query<{ current_version_id: string | null }>(
      "select current_version_id from documents where id=$1",
      [documentId]
    );
    if (state.rows.length !== 1 || state.rows[0]?.current_version_id !== result.reference)
      throw new Error(`document current-version guard mismatch: ${name}`);
    return result.reference;
  };
  const firstVersionId = await contribute("charter-a1", documentAId, title, firstBody, null, false);
  const secondVersionId = await contribute(
    "charter-a2",
    documentAId,
    title,
    pack("Phase two drilling: review Δ samples and the synthetic budget."),
    firstVersionId,
    true
  );
  const documentBVersionId = await contribute(
    "minutes-b1",
    documentBId,
    "Mining Exploration Co. synthetic minutes",
    "# Synthetic minutes\n\nThe directors reviewed the exploration programme and recorded comments.\n",
    null,
    false
  );
  let rejection: unknown;
  try {
    await service.executeDirect(principal, "create_document_version", {
      schema_version: TOOL_INPUT_SCHEMA_VERSION,
      board_id: actor.boardId,
      document_id: rejectedDocumentId,
      title: "Synthetic malformed submission",
      media_type: "application/json",
      schema_name: "boardagent.board-pack.v1",
      canonical_body: '{"duplicate":1,"duplicate":2}',
      expected_current_version_id: null,
      idempotency_key: "document-metadata-fixture-rejected"
    });
  } catch (error) {
    rejection = error;
  }
  if (
    !(rejection instanceof Error) ||
    !/invalid_canonical_content.*validation attempt/iu.test(rejection.message)
  )
    throw new Error(
      "normal malformed document contribution did not produce the expected persisted validation rejection",
      { cause: rejection }
    );
  attempts.push(Object.freeze({ name: "rejected", outcome: "rejected", reference: null }));
  const rejectedState = await pool.query<{ documents: string; versions: string }>(
    "select (select count(*)::text from documents where id=$1) as documents,(select count(*)::text from document_versions where document_id=$1) as versions",
    [rejectedDocumentId]
  );
  if (rejectedState.rows[0]?.documents !== "0" || rejectedState.rows[0]?.versions !== "0")
    throw new Error("rejected document unexpectedly retained a document/version");
  const acceptedAttempt = async (versionId: string): Promise<string> => {
    const found = await pool.query<{ id: string }>(
      "select id from document_validation_attempts where actor_member_id=$1 and board_id=$2 and result='accepted' and accepted_document_version_id=$3",
      [actor.memberId, actor.boardId, versionId]
    );
    if (found.rows.length !== 1 || !found.rows[0])
      throw new Error("accepted validation attempt fixture is not unique");
    return found.rows[0].id;
  };
  const firstAcceptedAttemptId = await acceptedAttempt(firstVersionId),
    acceptedAttemptId = await acceptedAttempt(secondVersionId);
  const rejected = await pool.query<{ id: string }>(
    "select id from document_validation_attempts where actor_member_id=$1 and board_id=$2 and result='rejected' and accepted_document_version_id is null",
    [actor.memberId, actor.boardId]
  );
  if (rejected.rows.length !== 1 || !rejected.rows[0])
    throw new Error("rejected validation attempt fixture is not unique");
  const rejectedAttemptId = rejected.rows[0].id;
  let grewA = false,
    createdThird = false;
  return {
    actor,
    principal,
    documentAId,
    documentBId,
    rejectedDocumentId,
    absentDocumentId: testId(286_080),
    absentVersionId: testId(286_081),
    absentAttemptId: testId(286_082),
    firstVersionId,
    secondVersionId,
    documentBVersionId,
    firstAcceptedAttemptId,
    acceptedAttemptId,
    rejectedAttemptId,
    attempts,
    growDocumentA: async () => {
      if (grewA) throw new Error("document A fixture growth already used");
      grewA = true;
      return contribute(
        "charter-a3",
        documentAId,
        title,
        pack("Phase three drilling: review Γ samples and the synthetic budget."),
        secondVersionId,
        true
      );
    },
    createThirdDocument: async () => {
      if (createdThird) throw new Error("third document fixture creation already used");
      createdThird = true;
      const documentId = testId(286_040);
      const versionId = await contribute(
        "programme-c1",
        documentId,
        "Mining Exploration Co. supplemental programme",
        "# Synthetic supplemental programme\n\nRecord the next exploration meeting and its supporting materials.\n",
        null,
        false
      );
      return { documentId, versionId };
    }
  };
}
