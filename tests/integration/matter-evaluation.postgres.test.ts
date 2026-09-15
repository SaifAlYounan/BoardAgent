import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import {
  PgBoardAgentSurfaceService,
  type BoardAgentSurfaceService,
  type SurfacePrincipal
} from "../../artifacts/server/src/index.js";
import { TOOL_INPUT_SCHEMA_VERSION, canonicalSha256 } from "../../lib/contracts/src/index.js";
import {
  appendAuditEventsInTransaction,
  evaluateMatterInTransaction,
  migrate,
  withRequestTransaction,
  type EvaluateMatterInput
} from "../../lib/db/src/index.js";
import {
  seedAdditionalAuthorizedActor,
  seedAuthorizedActor,
  testHash,
  testId
} from "../helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_matter_eval_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 6 });
  try {
    await migrate(pool, MIGRATIONS, "matter-evaluation-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

async function seedMatterFixture(pool: Pool, ambiguous = false) {
  const secretary = await seedAuthorizedActor(pool, {
    seatRole: "voting_member",
    scopes: ["secretariat:admin"],
    isSecretary: true
  });
  const outsider = await seedAdditionalAuthorizedActor(pool, secretary, {
    idBase: 100,
    seatRole: "voting_member",
    scopes: ["secretariat:admin"]
  });
  const profileId = testId(200);
  const rulesetId = testId(201);
  const approvalRuleIds = [testId(202), testId(203)] as const;
  const matterTypeId = testId(204);
  const ruleIds = [testId(205), testId(206)] as const;
  const documentId = testId(207);
  const documentVersionId = testId(208);
  const sourceBytes = Buffer.from("# Charter\nClause 7.2 reserved matters.\n", "utf8");
  const sourceSha256 = canonicalSha256({
    schemaVersion: "boardagent.synthetic-charter.v1",
    text: sourceBytes.toString("utf8")
  });
  const matterDefinition = {
    code: "investment",
    fields: [{ name: "amount", type: "integer" as const, required: true, minimum: 0 }]
  };
  const conditions = ambiguous
    ? ([
        { kind: "number_gte" as const, field: "amount", value: 1000 },
        { kind: "number_gte" as const, field: "amount", value: 1000 }
      ] as const)
    : ([
        { kind: "exists" as const, field: "amount" },
        { kind: "number_gte" as const, field: "amount", value: 1000 }
      ] as const);

  for (const [index, approvalRuleId] of approvalRuleIds.entries()) {
    await pool.query(
      `insert into approval_rules(
         id,organization_id,board_id,schema_version,threshold_numerator,
         threshold_denominator,quorum_numerator,quorum_denominator,approval_denominator,
         abstentions_count_for_quorum,tie_behavior,proxy_policy,close_mode,canonical_sha256,
         created_by
       ) values ($1,$2,$3,'boardagent.approval-rule.v1',$4,3,1,2,'eligible',true,'reject',
         'principal_supersedes_proxy','secretariat_confirmed',$5,$6)`,
      [
        approvalRuleId,
        secretary.organizationId,
        secretary.boardId,
        index + 1,
        testHash(40 + index),
        secretary.memberId
      ]
    );
  }
  await pool.query(
    `insert into governance_profiles(
       id,organization_id,board_id,version,state,schema_version,canonical_payload,
       canonical_sha256,source_agreement_references,activation_consent_record_id,created_by,
       activated_at
     ) values ($1,$2,$3,1,'active','boardagent.governance-profile.v1','{}',$4,'[]',$5,$6,
       transaction_timestamp())`,
    [
      profileId,
      secretary.organizationId,
      secretary.boardId,
      testHash(42),
      secretary.consentRecordId,
      secretary.memberId
    ]
  );
  await pool.query(
    `insert into rulesets(
       id,organization_id,board_id,profile_id,version,state,schema_version,canonical_payload,
       canonical_sha256,activation_consent_record_id,created_by,activated_at
     ) values ($1,$2,$3,$4,1,'active','boardagent.ruleset.v1','{}',$5,$6,$7,
       transaction_timestamp())`,
    [
      rulesetId,
      secretary.organizationId,
      secretary.boardId,
      profileId,
      testHash(43),
      secretary.consentRecordId,
      secretary.memberId
    ]
  );
  await pool.query(
    `update boards
        set current_governance_profile_id=$1,current_ruleset_id=$2,row_version=row_version+1
      where id=$3`,
    [profileId, rulesetId, secretary.boardId]
  );
  for (const [index, approvalRuleId] of approvalRuleIds.entries()) {
    await pool.query(
      `insert into governance_rule_templates(
         id,profile_id,code,approval_rule_id,exact_rule_payload,canonical_sha256
       ) values ($1,$2,$3,$4,'{}',$5)`,
      [
        testId(220 + index),
        profileId,
        `investment_rule_${String(index + 1)}`,
        approvalRuleId,
        testHash(70 + index)
      ]
    );
  }
  await pool.query(
    `insert into documents(id,organization_id,board_id,title,created_by)
     values ($1,$2,$3,'Synthetic charter',$4)`,
    [documentId, secretary.organizationId, secretary.boardId, secretary.memberId]
  );
  await pool.query(
    `insert into document_versions(
       id,organization_id,board_id,document_id,version,media_type,
       canonicalization_version,canonical_bytes,byte_length,sha256,canonical_metadata,created_by
     ) values ($1,$2,$3,$4,1,'text/markdown; charset=utf-8','RFC8785+NFC-LF-v1',$5,$6,$7,
       '{}',$8)`,
    [
      documentVersionId,
      secretary.organizationId,
      secretary.boardId,
      documentId,
      sourceBytes,
      sourceBytes.length,
      Buffer.from(sourceSha256, "hex"),
      secretary.memberId
    ]
  );
  await pool.query(
    "update documents set current_version_id=$1,row_version=row_version+1 where id=$2",
    [documentVersionId, documentId]
  );
  await pool.query(
    `insert into matter_types(id,ruleset_id,code,name,strict_fact_schema,schema_sha256)
     values ($1,$2,'investment','Investment', $3,$4)`,
    [
      matterTypeId,
      rulesetId,
      JSON.stringify(matterDefinition),
      Buffer.from(canonicalSha256(matterDefinition), "hex")
    ]
  );
  for (const [index, ruleId] of ruleIds.entries()) {
    const condition = conditions[index]!;
    await pool.query(
      `insert into ruleset_rules(
         id,ruleset_id,matter_type_id,priority,specificity,condition_tree,
         approval_rule_id,canonical_sha256
       ) values ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        ruleId,
        rulesetId,
        matterTypeId,
        ambiguous ? 10 : index === 0 ? 1 : 10,
        ambiguous ? 5 : index === 0 ? 1 : 5,
        JSON.stringify(condition),
        approvalRuleIds[index],
        Buffer.from(canonicalSha256({ condition, approvalRuleId: approvalRuleIds[index] }), "hex")
      ]
    );
    await pool.query(
      `insert into rule_citations(
         id,rule_id,source_document_version_id,source_document_sha256,clause,locator
       ) values ($1,$2,$3,$4,'Charter 7.2',$5)`,
      [
        testId(210 + index),
        ruleId,
        documentVersionId,
        Buffer.from(sourceSha256, "hex"),
        index === 0 ? "general matters" : "reserved matters"
      ]
    );
  }
  return {
    secretary,
    outsider,
    profileId,
    rulesetId,
    approvalRuleIds,
    matterTypeId,
    ruleIds,
    sourceSha256,
    documentVersionId
  };
}

function matterInput(
  fixture: Awaited<ReturnType<typeof seedMatterFixture>>,
  overrides: Partial<EvaluateMatterInput> = {}
): EvaluateMatterInput {
  return {
    organizationId: fixture.secretary.organizationId,
    boardId: fixture.secretary.boardId,
    matterTypeId: fixture.matterTypeId,
    matterTypeCode: "investment",
    facts: { amount: 2000 },
    expectedProfileId: fixture.profileId,
    expectedRulesetId: fixture.rulesetId,
    evaluationId: testId(300),
    idempotencyRecordId: testId(301),
    idempotencyKey: "evaluate-investment-matter-0001",
    auditEventId: testId(302),
    ...overrides
  };
}

const unavailableReads: Pick<BoardAgentSurfaceService, "executeRead" | "readResource"> = {
  executeRead: async () => {
    throw new Error("read not used by matter-evaluation surface test");
  },
  readResource: async () => {
    throw new Error("resource read not used by matter-evaluation surface test");
  }
};

function surfacePrincipal(
  fixture: Awaited<ReturnType<typeof seedMatterFixture>>
): SurfacePrincipal {
  return {
    organizationId: fixture.secretary.organizationId,
    memberId: fixture.secretary.memberId,
    serviceOrigin: "https://boardagent.test",
    clientId: fixture.secretary.clientId,
    protocolClientId: "https://governance-agent.test/client.json",
    accessTokenRecordId: fixture.secretary.accessTokenRecordId,
    tokenJti: fixture.secretary.tokenJti,
    keyId: "test-oauth",
    scopes: ["secretariat:admin"],
    roles: ["secretariat"],
    boardIds: [fixture.secretary.boardId]
  };
}

describe("persisted matter-evaluation transaction", () => {
  it("evaluates the caller-bound active profile, ruleset and matter type through the direct surface", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedMatterFixture(pool);
      let nextId = 10_000;
      const surface = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableReads,
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(nextId++)
      });
      const input = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "surface-evaluate-matter-0001",
        board_id: fixture.secretary.boardId,
        matter_type_id: fixture.matterTypeId,
        facts: {
          schema_version: "boardagent.investment-facts.v1",
          values: { amount: 2000 }
        },
        expected_profile_id: fixture.profileId,
        expected_ruleset_id: fixture.rulesetId
      } as const;
      const evaluated = await surface.executeDirect(
        surfacePrincipal(fixture),
        "evaluate_matter",
        input
      );
      expect(evaluated).toMatchObject({
        tool: "evaluate_matter",
        status: "accepted",
        data: {
          status: "matched",
          matched_rule_id: fixture.ruleIds[1],
          selected_approval_rule_id: fixture.approvalRuleIds[1],
          replayed: false
        }
      });
      const replayed = await surface.executeDirect(
        surfacePrincipal(fixture),
        "evaluate_matter",
        input
      );
      expect(replayed).toMatchObject({ status: "already_applied", data: { replayed: true } });
    });
  });

  it("persists the unique deterministic winner, citations and safe concurrent replay", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedMatterFixture(pool);
      const input = matterInput(fixture);
      const results = await Promise.all([
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => evaluateMatterInTransaction(client, input),
          { assumeRole: "boardagent_server" }
        ),
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => evaluateMatterInTransaction(client, input),
          { assumeRole: "boardagent_server" }
        )
      ]);
      expect(results.map(({ replayed }) => replayed).toSorted()).toEqual([false, true]);
      const fresh = results.find(({ replayed }) => !replayed);
      expect(fresh).toMatchObject({
        status: "matched",
        matchedRuleId: fixture.ruleIds[1],
        selectedApprovalRuleId: fixture.approvalRuleIds[1]
      });
      const persisted = await pool.query<{
        canonical_facts: Record<string, unknown>;
        candidate_rule_ids: string[];
        citation_snapshot: unknown[];
        result: string;
        matched_rule_id: string;
        result_sha256: Buffer;
      }>(
        `select canonical_facts,candidate_rule_ids,citation_snapshot,result,matched_rule_id,
                result_sha256
           from matter_evaluations where id=$1`,
        [input.evaluationId]
      );
      expect(persisted.rows[0]).toMatchObject({
        canonical_facts: { amount: 2000 },
        candidate_rule_ids: [fixture.ruleIds[1]],
        result: "matched",
        matched_rule_id: fixture.ruleIds[1]
      });
      expect(persisted.rows[0]?.citation_snapshot).toEqual([
        {
          clause: "Charter 7.2",
          locator: "reserved matters",
          ruleId: fixture.ruleIds[1],
          sourceDocumentSha256: fixture.sourceSha256,
          sourceDocumentVersionId: fixture.documentVersionId
        }
      ]);
      expect(persisted.rows[0]?.result_sha256.toString("hex")).toBe(fresh?.resultSha256);
      const audit = await pool.query<{ event_type: string }>(
        "select event_type from audit_events where id=$1",
        [input.auditEventId]
      );
      expect(audit.rows).toEqual([{ event_type: "matter_evaluated" }]);
    });
  });

  it("persists missing and ambiguous fail-closed results and refuses a nonsecretary", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedMatterFixture(pool, true);
      await expect(
        withRequestTransaction(
          pool,
          fixture.outsider.context,
          (client) => evaluateMatterInTransaction(client, matterInput(fixture)),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "matter_evaluation_unavailable" });
      const missing = await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) =>
          evaluateMatterInTransaction(
            client,
            matterInput(fixture, {
              facts: {},
              evaluationId: testId(320),
              idempotencyRecordId: testId(321),
              idempotencyKey: "evaluate-missing-matter-0001",
              auditEventId: testId(322)
            })
          ),
        { assumeRole: "boardagent_server" }
      );
      expect(missing).toMatchObject({ status: "missing", missingFields: ["amount"] });
      const ambiguous = await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) =>
          evaluateMatterInTransaction(
            client,
            matterInput(fixture, {
              evaluationId: testId(330),
              idempotencyRecordId: testId(331),
              idempotencyKey: "evaluate-ambiguous-matter-0001",
              auditEventId: testId(332)
            })
          ),
        { assumeRole: "boardagent_server" }
      );
      expect(ambiguous).toMatchObject({
        status: "ambiguous",
        candidateRuleIds: [...fixture.ruleIds].toSorted()
      });
      const rows = await pool.query<{ result: string }>(
        "select result from matter_evaluations order by id"
      );
      expect(rows.rows.map(({ result }) => result).toSorted()).toEqual(["ambiguous", "missing"]);
    });
  });

  it("rolls the evaluation and idempotency row back when final audit append fails", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedMatterFixture(pool);
      const input = matterInput(fixture);
      await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) =>
          appendAuditEventsInTransaction(client, [
            {
              organizationId: fixture.secretary.organizationId,
              event: {
                eventId: input.auditEventId,
                eventType: "context_read",
                actorMemberId: fixture.secretary.memberId,
                actorClientId: fixture.secretary.clientId,
                tokenJti: fixture.secretary.tokenJti,
                entityType: "board",
                entityId: fixture.secretary.boardId,
                boardId: fixture.secretary.boardId,
                origin: "mcp",
                details: { seededFailure: true },
                schemaVersion: 1
              }
            }
          ]),
        { assumeRole: "boardagent_server" }
      );
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => evaluateMatterInTransaction(client, input),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow();
      const rolledBack = await pool.query<{ evaluations: string; idempotency: string }>(
        `select
           (select count(*)::text from matter_evaluations where id=$1) as evaluations,
           (select count(*)::text from idempotency_records where id=$2) as idempotency`,
        [input.evaluationId, input.idempotencyRecordId]
      );
      expect(rolledBack.rows).toEqual([{ evaluations: "0", idempotency: "0" }]);
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => evaluateMatterInTransaction(client, { ...input, auditEventId: testId(303) }),
          { assumeRole: "boardagent_server" }
        )
      ).resolves.toMatchObject({ replayed: false, status: "matched" });
    });
  });

  it("rejects unknown facts before persistence", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedMatterFixture(pool);
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            evaluateMatterInTransaction(
              client,
              matterInput(fixture, { facts: { amount: 2, surprise: true } })
            ),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow(/unknown matter fact/u);
      const count = await pool.query<{ count: string }>(
        "select count(*)::text as count from matter_evaluations"
      );
      expect(count.rows[0]?.count).toBe("0");
    });
  });
});
