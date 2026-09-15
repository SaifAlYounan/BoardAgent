import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";

import { Pool, type PoolClient, type QueryResult } from "pg";
import { describe, expect, it } from "vitest";

import { canonicalJson, sha256Hex, type JsonValue } from "../../lib/contracts/src/index.js";
import {
  COMMUNICATIONS_PREFLIGHT_SQL,
  COMMUNICATIONS_CONTENT_SQL,
  PROPOSAL_INSPECTION_SQL,
  loadAdmittedCommunicationsList,
  type CommunicationsListInput,
  type CommunicationsListMetadata,
  type CommunicationsPageRow
} from "../../artifacts/server/src/communications-list-read.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";

import {
  approveProposalInTransaction,
  askSecretariatInTransaction,
  closeSecretariatRequestInTransaction,
  loadMigrations,
  migrate,
  proposeActionInTransaction,
  rejectProposalInTransaction,
  replySecretariatRequestInTransaction,
  withdrawProposalInTransaction,
  withRequestTransaction,
  type ApproveProposalInput,
  type AskSecretariatInput,
  type ProposeActionInput
} from "../../lib/db/src/index.js";
import {
  seedAdditionalAuthorizedActor,
  seedAuthorizedActor,
  testId,
  type AuthorizedActorFixture
} from "../helpers/authorized-actor.js";
import { dropClosedTestDatabase } from "../helpers/drop-test-database.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

async function withDatabase<T>(
  run: (pool: Pool) => Promise<T>,
  migrations = MIGRATIONS
): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_communications_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 8 });
  let passed = false;
  try {
    await migrate(pool, migrations, "communications-test");
    const result = await run(pool);
    passed = true;
    return result;
  } finally {
    await pool.end();
    try {
      if (passed) await dropClosedTestDatabase(admin, database);
      else process.stderr.write(`Preserved failed communications fixture: ${database}\n`);
    } finally {
      await admin.end();
    }
  }
}

function request<T>(
  pool: Pool,
  actor: AuthorizedActorFixture,
  run: Parameters<typeof withRequestTransaction<T>>[2]
): Promise<T> {
  return withRequestTransaction(pool, actor.context, run, {
    assumeRole: "boardagent_server",
    isolation: "serializable"
  });
}

function proposalInput(
  actor: AuthorizedActorFixture,
  base: number,
  key: string
): ProposeActionInput {
  return {
    organizationId: actor.organizationId,
    proposalId: testId(base),
    boardId: actor.boardId,
    proposalType: "meeting",
    title: "Call a strategy meeting",
    payload: {
      schema_version: "boardagent.proposal.meeting.v1",
      values: { purpose: "Review the operating plan" }
    },
    references: [],
    idempotencyRecordId: testId(base + 1),
    idempotencyKey: key,
    auditEventId: testId(base + 2)
  };
}

function askInput(actor: AuthorizedActorFixture, base: number, key: string): AskSecretariatInput {
  return {
    organizationId: actor.organizationId,
    requestId: testId(base),
    initialTurnId: testId(base + 1),
    boardId: actor.boardId,
    topic: "Next board calendar",
    message: "Please confirm the proposed date for the next board meeting.",
    references: [],
    idempotencyRecordId: testId(base + 2),
    idempotencyKey: key,
    auditEventId: testId(base + 3)
  };
}

describe("proposal and secretariat communication transactions", () => {
  it("admits communications lists before construction under actual role and fresh frontiers", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["member:propose", "secretariat:message", "governance:read"]
      });
      const secretary = await seedAdditionalAuthorizedActor(pool, actor, {
        idBase: 500,
        seatRole: "management",
        scopes: ["secretariat:admin", "secretariat:message", "governance:read"],
        isSecretary: true
      });
      const proposal = proposalInput(actor, 2000, "admission-proposal-main");
      const facts = {
        schema_version: "boardagent.admission.v1",
        values: {
          huge: 1e308,
          tiny: 5e-324,
          nul: "\u0000",
          escaped: 'quote"slash\\漢é'
        }
      };
      await request(pool, actor, (client) =>
        proposeActionInTransaction(client, { ...proposal, payload: facts })
      );
      const disposed = proposalInput(actor, 2100, "admission-proposal-disposed");
      await request(pool, actor, (client) => proposeActionInTransaction(client, disposed));
      await request(pool, secretary, (client) =>
        rejectProposalInTransaction(client, {
          organizationId: actor.organizationId,
          proposalId: disposed.proposalId,
          dispositionId: testId(2110),
          reason: "Reviewed reason 漢é".repeat(32),
          idempotencyRecordId: testId(2111),
          idempotencyKey: "admission-dispose",
          auditEventId: testId(2112)
        })
      );
      await request(pool, actor, (client) =>
        proposeActionInTransaction(
          client,
          proposalInput(actor, 2200, "admission-proposal-lookahead")
        )
      );
      const asked = askInput(actor, 3000, "admission-request-main");
      const reference = { uri: "board://fixtures/record-a", sha256: "a".repeat(64) };
      await request(pool, actor, (client) =>
        askSecretariatInTransaction(client, {
          ...asked,
          message: "Initial request 漢é".repeat(128),
          references: [reference]
        })
      );
      await request(pool, actor, (client) =>
        askSecretariatInTransaction(client, askInput(actor, 3100, "admission-request-lookahead"))
      );
      const reply = (base: number, text: string) =>
        request(pool, secretary, (client) =>
          replySecretariatRequestInTransaction(client, {
            organizationId: actor.organizationId,
            requestId: asked.requestId,
            turnId: testId(base),
            reply: text,
            idempotencyRecordId: testId(base + 1),
            idempotencyKey: `admission-reply-${String(base)}`,
            auditEventId: testId(base + 2)
          })
        );
      for (let index = 0; index < 12; index += 1)
        await reply(4000 + index * 10, `Reply ${String(index)} 漢é `.repeat(256));

      type Hook = (sql: string, values: unknown[], client: PoolClient) => Promise<QueryResult>;
      const input = (kind: "secretariat" | "proposals", limit = 2): CommunicationsListInput => ({
        kind,
        boardId: actor.boardId,
        memberId: secretary.memberId,
        state: kind === "proposals" ? "pending" : null,
        cursorAt: null,
        cursorId: null,
        limit
      });
      const parameters = (value: CommunicationsListInput) => [
        value.boardId,
        value.memberId,
        value.state,
        value.cursorAt,
        value.cursorId,
        value.limit + 1
      ];
      const read = async (
        value: CommunicationsListInput,
        reader = secretary,
        hook?: Hook,
        manager = new ResponseAllocationManager()
      ) => {
        const baseline = manager.accounting.usedUnits;
        const owner = manager.openRequest(new AbortController().signal);
        try {
          return await owner.produce(() =>
            withRequestTransaction(
              pool,
              reader.context,
              async (client) => {
                const facade = {
                  query: (sql: string, values: unknown[] = []) =>
                    hook ? hook(sql, values, client) : client.query(sql, values)
                } as unknown as PoolClient;
                return loadAdmittedCommunicationsList(facade, {
                  ...value,
                  memberId: reader.memberId
                });
              },
              { assumeRole: "boardagent_server", isolation: "read committed" }
            )
          );
        } finally {
          const beforeTerminal = manager.accounting.usedUnits;
          owner.nativeTerminal();
          expect(manager.accounting.usedUnits).toBe(beforeTerminal);
          owner.collectorSettled();
          expect(manager.accounting.usedUnits).toBe(baseline);
        }
      };
      const auditCount = async () =>
        (await pool.query<{ count: string }>("select count(*)::text as count from audit_events"))
          .rows[0]!.count;
      const beforeReads = await auditCount();
      const proposals = await read(input("proposals"));
      expect(proposals).toHaveLength(2);
      const main = proposals.find((row) => row.cursor_id === proposal.proposalId)!;
      const expectedPayload = JSON.parse(
        canonicalJson({
          schemaVersion: "boardagent.proposal.v1",
          proposalId: proposal.proposalId,
          boardId: actor.boardId,
          proposalType: proposal.proposalType,
          title: proposal.title,
          payload: facts,
          references: []
        })
      );
      expect(main.item).toEqual({
        proposal_id: proposal.proposalId,
        board_id: actor.boardId,
        proposer_member_id: actor.memberId,
        proposal_type: proposal.proposalType,
        title: proposal.title,
        schema_version: "boardagent.proposal.v1",
        payload: expectedPayload,
        payload_sha256: sha256Hex(canonicalJson(expectedPayload)),
        references: [],
        state: "pending",
        row_version: "1",
        disposition: null,
        created_at: main.cursor_at
      });
      const requests = await read(input("secretariat"));
      expect(requests).toHaveLength(2);
      const thread = requests.find((row) => row.cursor_id === asked.requestId)!.item as Record<
        string,
        JsonValue
      >;
      expect(Object.keys(thread).sort()).toEqual(
        [
          "request_id",
          "board_id",
          "requester_member_id",
          "topic",
          "state",
          "current_turn_id",
          "row_version",
          "turns",
          "created_at",
          "closed_at"
        ].sort()
      );
      const turns = thread["turns"] as Record<string, JsonValue>[];
      expect(turns).toHaveLength(13);
      expect(turns.map((turn) => turn["ordinal"])).toEqual(
        Array.from({ length: 13 }, (_, i) => i + 1)
      );
      for (const turn of turns)
        expect(Object.keys(turn).sort()).toEqual(
          [
            "turn_id",
            "ordinal",
            "turn_kind",
            "author_member_id",
            "author_role",
            "canonical_text",
            "sha256",
            "resource_references",
            "created_at"
          ].sort()
        );
      expect(turns[0]!["resource_references"]).toEqual([reference]);
      expect((await read(input("secretariat", 1))).length).toBe(2); // Actual lookahead remains charged.
      const rejected = await read({ ...input("proposals"), state: "rejected" });
      expect(rejected).toHaveLength(1);
      const rejection = rejected[0]!.item as Record<string, JsonValue>;
      expect(Object.keys(rejection["disposition"] as object).sort()).toEqual(
        [
          "disposition_id",
          "disposition",
          "reason",
          "resulting_draft_id",
          "actor_member_id",
          "created_at"
        ].sort()
      );

      // Enumerate actual returned scalar values independently of the SQL extraction.
      const utf8 = (object: Record<string, JsonValue>, keys: readonly string[]) =>
        keys.reduce(
          (sum, key) =>
            sum +
            (object[key] === null ? 0n : BigInt(Buffer.byteLength(String(object[key]), "utf8"))),
          0n
        );
      const referenceMetrics = (value: JsonValue) => {
        const refs = value as Record<string, JsonValue>[];
        return {
          count: BigInt(refs.length),
          utf8: refs.reduce((sum, ref) => sum + utf8(ref, ["uri", "sha256"]), 0n)
        };
      };
      for (const [value, rows] of [
        [input("secretariat"), requests],
        [input("proposals"), proposals],
        [{ ...input("proposals"), state: "rejected" }, rejected]
      ] as const) {
        const metadata = await withRequestTransaction(
          pool,
          secretary.context,
          (client) =>
            client.query<CommunicationsListMetadata>(
              COMMUNICATIONS_PREFLIGHT_SQL[value.kind],
              parameters(value)
            ),
          { assumeRole: "boardagent_server", isolation: "read committed" }
        );
        for (const row of rows) {
          const scalar = metadata.rows.find((item) => item.id === row.cursor_id)!;
          const item = row.item as Record<string, JsonValue>;
          let j: bigint, p: bigint, o: bigint;
          if (value.kind === "secretariat") {
            const children = item["turns"] as Record<string, JsonValue>[];
            const count = BigInt(children.length);
            const rootBytes = utf8(item, [
              "request_id",
              "board_id",
              "requester_member_id",
              "topic",
              "state",
              "current_turn_id",
              "row_version",
              "created_at",
              "closed_at"
            ]);
            const childBytes = children.reduce(
              (sum, child) =>
                sum +
                utf8(child, [
                  "turn_id",
                  "ordinal",
                  "turn_kind",
                  "author_member_id",
                  "author_role",
                  "canonical_text",
                  "sha256",
                  "created_at"
                ]),
              0n
            );
            const refs = children.map((child) => referenceMetrics(child["resource_references"]!));
            const refCount = refs.reduce((sum, ref) => sum + ref.count, 0n);
            const refBytes = refs.reduce((sum, ref) => sum + ref.utf8, 0n);
            j =
              199n +
              6n * rootBytes +
              2n +
              count * 193n +
              6n * childBytes +
              count * 2n +
              refCount * 33n +
              6n * refBytes;
            p = 10n + 9n * count + 2n * refCount;
            o = 2n + 2n * count + refCount;
            expect(scalar.canonical_bytes).toBe("0");
          } else {
            const rootBytes = utf8(item, [
              "proposal_id",
              "board_id",
              "proposer_member_id",
              "proposal_type",
              "title",
              "schema_version",
              "payload_sha256",
              "state",
              "row_version",
              "created_at"
            ]);
            const refs = referenceMetrics(item["references"]!);
            const disposition = item["disposition"] as Record<string, JsonValue> | null;
            const count = disposition === null ? 0n : 1n;
            const dispositionBytes =
              disposition === null
                ? 0n
                : utf8(disposition, [
                    "disposition_id",
                    "disposition",
                    "reason",
                    "resulting_draft_id",
                    "actor_member_id",
                    "created_at"
                  ]);
            j =
              269n +
              6n * rootBytes +
              2n +
              refs.count * 33n +
              6n * refs.utf8 +
              count * 136n +
              6n * dispositionBytes;
            p = 13n + 2n * refs.count + 6n * count;
            o = 2n + refs.count + count;
            expect(scalar.canonical_bytes).toBe(
              String(Buffer.byteLength(canonicalJson(item["payload"])))
            );
          }
          expect([scalar.json_upper, scalar.property_count, scalar.object_count]).toEqual([
            j.toString(),
            p.toString(),
            o.toString()
          ]);
        }
      }
      expect(await auditCount()).toBe(beforeReads);

      await pool.query(`create function public.communications_text_fault() returns text
        language plpgsql volatile as $$ begin raise exception 'communications content evaluated'; end $$`);
      await pool.query(`create function public.communications_bytea_fault() returns bytea
        language plpgsql volatile as $$ begin raise exception 'communications raw evaluated'; end $$`);
      await pool.query(
        "grant execute on function public.communications_text_fault(), public.communications_bytea_fault() to boardagent_server"
      );
      const contentFault = COMMUNICATIONS_CONTENT_SQL.secretariat.replace(
        "'request_id',request.id",
        "'request_id',public.communications_text_fault()"
      );
      expect(contentFault).not.toBe(COMMUNICATIONS_CONTENT_SQL.secretariat);
      const rawFault = PROPOSAL_INSPECTION_SQL.replace(
        "select proposal.canonical_payload from proposals",
        "select public.communications_bytea_fault() from proposals"
      );
      expect(rawFault).not.toBe(PROPOSAL_INSPECTION_SQL);
      await expect(
        read(input("secretariat"), secretary, (sql, values, client) =>
          client.query(sql === COMMUNICATIONS_CONTENT_SQL.secretariat ? contentFault : sql, values)
        )
      ).rejects.toThrow("communications content evaluated");
      await expect(
        read(input("proposals"), secretary, (sql, values, client) =>
          client.query(sql === PROPOSAL_INSPECTION_SQL ? rawFault : sql, values)
        )
      ).rejects.toThrow("communications raw evaluated");
      await expect(
        read(input("secretariat"), secretary, (sql, values, client) =>
          client.query(
            sql === COMMUNICATIONS_PREFLIGHT_SQL.secretariat
              ? sql.replace(
                  "octet_length(checked.value->>'uri')",
                  "octet_length(public.communications_text_fault())"
                )
              : sql,
            values
          )
        )
      ).rejects.toThrow("communications content evaluated");

      const saturated = new ResponseAllocationManager();
      const blockers: Array<{ release(): void }> = [];
      const small = responseAllocationPlan({
        kind: "document",
        representation: "tool",
        sourceId: "fixture-capacity-holder",
        sourceVersion: "1",
        sha256: "a".repeat(64),
        canonicalBytes: 0
      });
      for (let index = 0; index < 2048; index += 1) blockers.push(saturated.tryReserve(small));
      let loadedBeforeRefusal = 0;
      try {
        await expect(
          read(
            input("proposals"),
            secretary,
            async (sql, values, client) => {
              if (sql === PROPOSAL_INSPECTION_SQL || sql === COMMUNICATIONS_CONTENT_SQL.proposals)
                loadedBeforeRefusal += 1;
              return client.query(sql, values);
            },
            saturated
          )
        ).rejects.toThrow(ResponseAllocationUnavailable);
        expect(loadedBeforeRefusal).toBe(0);
      } finally {
        for (const blocker of blockers) blocker.release();
      }
      expect(saturated.accounting.usedUnits).toBe(0);

      let growthGateRows = 0;
      let postGrowthAudit = "";
      await expect(
        read(input("secretariat"), secretary, async (sql, values, client) => {
          if (sql === COMMUNICATIONS_PREFLIGHT_SQL.secretariat) {
            const selected = await client.query(sql, values);
            await reply(5000, "Growth 漢é".repeat(8192));
            postGrowthAudit = await auditCount();
            const fresh = await client.query<CommunicationsListMetadata>(sql, values);
            const old = selected.rows.find((row) => row.id === asked.requestId);
            const now = fresh.rows.find((row) => row.id === asked.requestId)!;
            expect(BigInt(now.json_upper)).toBeGreaterThan(BigInt(old.json_upper));
            return selected;
          }
          const result = await client.query(
            sql === COMMUNICATIONS_CONTENT_SQL.secretariat ? contentFault : sql,
            values
          );
          if (sql === COMMUNICATIONS_CONTENT_SQL.secretariat) {
            growthGateRows = result.rows.length;
            expect(result.rows.length).toBe(2);
            expect(result.rows.every((row) => row.fits === false && row.item === null)).toBe(true);
          }
          return result;
        })
      ).rejects.toThrow(ResponseAllocationUnavailable);
      expect(growthGateRows).toBe(2);
      expect(await auditCount()).toBe(postGrowthAudit);

      let newRootGate = false;
      await expect(
        read(input("secretariat", 1), secretary, async (sql, values, client) => {
          if (sql === COMMUNICATIONS_PREFLIGHT_SQL.secretariat) {
            const selected = await client.query(sql, values);
            await request(pool, actor, (writer) =>
              askSecretariatInTransaction(
                writer,
                askInput(actor, 6000, "admission-frontier-growth")
              )
            );
            return selected;
          }
          const result = await client.query(
            sql === COMMUNICATIONS_CONTENT_SQL.secretariat ? contentFault : sql,
            values
          );
          if (sql === COMMUNICATIONS_CONTENT_SQL.secretariat) {
            newRootGate = result.rows.every((row) => row.fits === false && row.item === null);
            expect(result.rows.some((row) => row.cursor_id === testId(6000))).toBe(true);
          }
          return result;
        })
      ).rejects.toThrow(ResponseAllocationUnavailable);
      expect(newRootGate).toBe(true);

      // Exercise the authorized SQL creation capability's stored-reference boundary,
      // not the public writer validator: only its candidate_references argument changes.
      const malformedReferences = [
        '[{"uri":1e10000,"sha256":"' + "a".repeat(64) + '"}]',
        "[1e10000]",
        JSON.stringify(
          Array.from({ length: 257 }, (_, index) => ({
            uri: `board://fixtures/${String(index)}`,
            sha256: "a".repeat(64)
          }))
        )
      ];
      for (let index = 0; index < malformedReferences.length; index += 1) {
        const base = 7000 + index * 100;
        const bad = proposalInput(actor, base, `admission-malformed-reference-${String(index)}`);
        let insertedThroughCapability = 0;
        await request(pool, actor, (client) =>
          proposeActionInTransaction(
            {
              query: async (sql: string, values: unknown[] = []) => {
                if (sql.includes("from boardagent_create_proposal(")) {
                  insertedThroughCapability += 1;
                  const replaced = [...values];
                  replaced[6] = malformedReferences[index];
                  return client.query(sql, replaced);
                }
                return client.query(sql, values);
              }
            } as unknown as PoolClient,
            bad
          )
        );
        expect(insertedThroughCapability).toBe(1);
        let metadataSeen = false;
        let laterLoads = 0;
        await expect(
          read(input("proposals", 1), secretary, async (sql, values, client) => {
            if (sql !== COMMUNICATIONS_PREFLIGHT_SQL.proposals) laterLoads += 1;
            // Select only the latest malformed row for the extraction fault oracle.
            const limited = [...values];
            limited[5] = 1;
            const guarded = sql.replace(
              "octet_length(checked.value->>'uri')",
              "octet_length(public.communications_text_fault())"
            );
            const selected = await client.query(guarded, limited);
            if (sql === COMMUNICATIONS_PREFLIGHT_SQL.proposals) {
              metadataSeen = true;
              expect(selected.rows).toHaveLength(1);
              expect(selected.rows[0]).toMatchObject({ id: bad.proposalId, supported: false });
            }
            return selected;
          })
        ).rejects.toThrow(ResponseAllocationUnavailable);
        expect(metadataSeen).toBe(true);
        expect(laterLoads).toBe(0);
        await request(pool, actor, (client) =>
          withdrawProposalInTransaction(client, {
            organizationId: actor.organizationId,
            proposalId: bad.proposalId,
            idempotencyRecordId: testId(base + 10),
            idempotencyKey: `admission-withdraw-${String(index)}`,
            auditEventId: testId(base + 11)
          })
        );
      }

      const revoke = async (reader: AuthorizedActorFixture) => {
        const changed = await pool.query<{ jti: string }>(
          "update access_token_records set revoked_at=transaction_timestamp() where jti=$1 and revoked_at is null returning jti",
          [reader.tokenJti]
        );
        expect(changed.rows).toEqual([{ jti: reader.tokenJti }]);
      };
      let secretaryPreflight = 0;
      const beforeRevocation = await auditCount();
      expect(
        await read(input("secretariat"), secretary, async (sql, values, client) => {
          const selected = await client.query(sql, values);
          if (sql === COMMUNICATIONS_PREFLIGHT_SQL.secretariat) {
            secretaryPreflight = selected.rows.length;
            expect(secretaryPreflight).toBeGreaterThan(0);
            await revoke(secretary);
          }
          return selected;
        })
      ).toEqual([]);
      expect(secretaryPreflight).toBeGreaterThan(0);
      const hiddenProposals = await withRequestTransaction(
        pool,
        secretary.context,
        (client) =>
          client.query(COMMUNICATIONS_PREFLIGHT_SQL.proposals, parameters(input("proposals"))),
        { assumeRole: "boardagent_server", isolation: "read committed" }
      );
      expect(hiddenProposals.rows).toEqual([]);

      // Diagnostic observation, not an assumed all-principal revocation guarantee.
      // The reviewed requester SELECT disjunct can differ from secretary readiness.
      let ownerBefore: string[] = [];
      let ownerAfter: readonly CommunicationsPageRow[] = [];
      let ownerOutcome = "returned";
      try {
        ownerAfter = await read(input("secretariat"), actor, async (sql, values, client) => {
          const selected = await client.query(sql, values);
          if (sql === COMMUNICATIONS_PREFLIGHT_SQL.secretariat) {
            ownerBefore = selected.rows.map((row) => row.id);
            expect(ownerBefore.length).toBeGreaterThan(0);
            await revoke(actor);
          }
          return selected;
        });
      } catch (error) {
        expect(error).toBeInstanceOf(ResponseAllocationUnavailable);
        ownerOutcome = "capacity_refused";
      }
      expect(ownerAfter.every((row) => ownerBefore.includes(row.cursor_id))).toBe(true);
      process.stdout.write(
        JSON.stringify({
          observation: "communications-requester-revocation",
          outcome: ownerOutcome,
          preflightIds: ownerBefore,
          returnedIds: ownerAfter.map((row) => row.cursor_id),
          returnedCount: ownerAfter.length
        }) + "\n"
      );
      expect(await auditCount()).toBe(beforeRevocation);
    });
  }, 60_000);

  it.each(["propose_action", "ask_secretariat"] as const)(
    "%s refuses new creation after board archival while preserving exact retries and entitled reads",
    async (operation) => {
      await withDatabase(async (pool) => {
        const actor = await seedAuthorizedActor(pool, {
          seatRole: "voting_member",
          scopes: ["member:propose", "secretariat:message", "governance:read"]
        });
        const secretary = await seedAdditionalAuthorizedActor(pool, actor, {
          idBase: 1000,
          seatRole: "management",
          scopes: ["secretariat:admin", "secretariat:message", "governance:read"],
          isSecretary: true
        });
        const create = (base: number, key: string) =>
          request(pool, actor, (client) =>
            operation === "propose_action"
              ? proposeActionInTransaction(client, proposalInput(actor, base, key))
              : askSecretariatInTransaction(client, askInput(actor, base, key))
          );
        const counts = async () =>
          (
            await pool.query<Record<string, string>>(
              `select
                 (select count(*)::text from proposals) as proposals,
                 (select count(*)::text from secretariat_requests) as requests,
                 (select count(*)::text from secretariat_request_turns) as turns,
                 (select count(*)::text from idempotency_records) as idempotency,
                 (select count(*)::text from audit_events) as audit`
            )
          ).rows[0];

        const existing = await create(800, "communication-before-archive-0001");
        expect(existing).toMatchObject({ replayed: false, objectId: testId(800) });
        const before = await counts();
        expect(before).toEqual({
          proposals: operation === "propose_action" ? "1" : "0",
          requests: operation === "ask_secretariat" ? "1" : "0",
          turns: operation === "ask_secretariat" ? "1" : "0",
          idempotency: "1",
          audit: "1"
        });

        // Reproduce the supported archive effect from migration 0069 while retaining
        // the already admitted managed context. This does not test fresh HTTP login.
        const archived = await pool.query<{ state: string; row_version: string }>(
          `update boards set state='archived',row_version=row_version+1
            where id=$1 and state='active' returning state,row_version::text`,
          [actor.boardId]
        );
        expect(archived.rows).toEqual([{ state: "archived", row_version: "2" }]);
        expect(await create(800, "communication-before-archive-0001")).toEqual({
          replayed: true,
          operation,
          objectId: testId(800),
          responseSha256: existing.responseSha256
        });

        const visibleTo = (reader: AuthorizedActorFixture) =>
          request(pool, reader, async (client) =>
            operation === "propose_action"
              ? (await client.query("select id from proposals where id=$1", [testId(800)])).rows
              : (
                  await client.query(
                    `select request.id,turn.canonical_text from secretariat_requests as request
                       join secretariat_request_turns as turn on turn.request_id=request.id
                      where request.id=$1`,
                    [testId(800)]
                  )
                ).rows
          );
        const retainedRows =
          operation === "propose_action"
            ? [{ id: testId(800) }]
            : [
                {
                  id: testId(800),
                  canonical_text: askInput(actor, 800, "unused-readback-key").message
                }
              ];
        expect(await visibleTo(secretary)).toEqual(retainedRows);
        expect(await visibleTo(actor)).toEqual(operation === "propose_action" ? [] : retainedRows);

        const outcome = await create(900, "communication-after-archive-0001").then(
          () => "created",
          (error: unknown) => {
            expect(error).toBeInstanceOf(Error);
            return (error as Error).message;
          }
        );
        expect({ outcome, counts: await counts() }).toEqual({
          outcome: expect.stringMatching(/unavailable/u),
          counts: before
        });

        // A retained success does not become authority after the original token is revoked.
        await pool.query(
          "update access_token_records set revoked_at=transaction_timestamp() where id=$1",
          [actor.accessTokenRecordId]
        );
        await expect(create(800, "communication-before-archive-0001")).rejects.toThrow(
          /unavailable/u
        );
        expect(await counts()).toEqual(before);
      });
    }
  );

  it.each(["propose_action", "ask_secretariat"] as const)(
    "%s serializes creation behind an archive already holding the board row",
    async (operation) => {
      await withDatabase(async (pool) => {
        const actor = await seedAuthorizedActor(pool, {
          seatRole: "voting_member",
          scopes: ["member:propose", "secretariat:message"]
        });
        const archive = await pool.connect();
        let archiveOpen = false;
        let settled = false;
        let creation: Promise<{ status: string; code: string }> | undefined;
        try {
          await archive.query("begin");
          archiveOpen = true;
          const archivePid = (
            await archive.query<{ pid: number }>("select pg_backend_pid() as pid")
          ).rows[0]!.pid;
          await archive.query(
            "update boards set state='archived',row_version=row_version+1 where id=$1",
            [actor.boardId]
          );
          const started = Promise.withResolvers<number>();
          creation = request(pool, actor, async (client) => {
            await client.query("set local statement_timeout='5s'");
            started.resolve(
              (await client.query<{ pid: number }>("select pg_backend_pid() as pid")).rows[0]!.pid
            );
            return operation === "propose_action"
              ? proposeActionInTransaction(
                  client,
                  proposalInput(actor, 1200, "proposal-archive-race-0001")
                )
              : askSecretariatInTransaction(
                  client,
                  askInput(actor, 1200, "request-archive-race-0001")
                );
          }).then(
            () => {
              settled = true;
              return { status: "created", code: "" };
            },
            (error: unknown) => {
              settled = true;
              return { status: "refused", code: String((error as { code?: unknown }).code ?? "") };
            }
          );
          const creationPid = await Promise.race([started.promise, creation.then(() => null)]);
          let blockedByArchive = false;
          const deadline = Date.now() + 3_000;
          while (creationPid !== null && !settled && Date.now() < deadline) {
            const waiting = await pool.query<{ blocked: boolean }>(
              "select $2::integer=any(pg_blocking_pids($1::integer)) as blocked",
              [creationPid, archivePid]
            );
            if (waiting.rows[0]?.blocked) {
              blockedByArchive = true;
              break;
            }
            await new Promise((resolve) => setTimeout(resolve, 20));
          }
          await archive.query("commit");
          archiveOpen = false;
          const outcome = await creation;
          const counts = await pool.query<Record<string, string>>(
            `select
               (select count(*)::text from proposals) as proposals,
               (select count(*)::text from secretariat_requests) as requests,
               (select count(*)::text from secretariat_request_turns) as turns,
               (select count(*)::text from idempotency_records) as idempotency,
               (select count(*)::text from audit_events) as audit`
          );
          expect({ blockedByArchive, outcome, counts: counts.rows[0] }).toEqual({
            blockedByArchive: true,
            outcome: { status: "refused", code: expect.stringMatching(/^(?:40001|P0002)$/u) },
            counts: { proposals: "0", requests: "0", turns: "0", idempotency: "0", audit: "0" }
          });
        } finally {
          try {
            if (archiveOpen) await archive.query("rollback");
            if (creation) await creation;
          } finally {
            archive.release();
          }
        }
      });
    }
  );

  it.each(["propose_action", "ask_secretariat"] as const)(
    "%s holds the board row until creation commits before archival",
    async (operation) => {
      await withDatabase(async (pool) => {
        const actor = await seedAuthorizedActor(pool, {
          seatRole: "voting_member",
          scopes: ["member:propose", "secretariat:message"]
        });
        const archive = await pool.connect();
        const ready = Promise.withResolvers<number>();
        const finishCreation = Promise.withResolvers<void>();
        let archiveOpen = false;
        let archiveSettled = false;
        let archiveUpdate: Promise<{ status: string; code: string }> | undefined;
        const creation = request(pool, actor, async (client) => {
          const pid = (await client.query<{ pid: number }>("select pg_backend_pid() as pid"))
            .rows[0]!.pid;
          const result =
            operation === "propose_action"
              ? await proposeActionInTransaction(
                  client,
                  proposalInput(actor, 1300, "proposal-create-first-0001")
                )
              : await askSecretariatInTransaction(
                  client,
                  askInput(actor, 1300, "request-create-first-0001")
                );
          ready.resolve(pid);
          await finishCreation.promise;
          return result;
        }).then(
          () => ({ status: "created", code: "" }),
          (error: unknown) => ({
            status: "refused",
            code: String((error as { code?: unknown }).code ?? "")
          })
        );
        try {
          const creationPid = await Promise.race([ready.promise, creation.then(() => null)]);
          expect(creationPid).not.toBeNull();
          await archive.query("begin");
          archiveOpen = true;
          await archive.query("set local statement_timeout='5s'");
          const archivePid = (
            await archive.query<{ pid: number }>("select pg_backend_pid() as pid")
          ).rows[0]!.pid;
          archiveUpdate = archive
            .query("update boards set state='archived',row_version=row_version+1 where id=$1", [
              actor.boardId
            ])
            .then(
              () => {
                archiveSettled = true;
                return { status: "archived", code: "" };
              },
              (error: unknown) => {
                archiveSettled = true;
                return {
                  status: "refused",
                  code: String((error as { code?: unknown }).code ?? "")
                };
              }
            );
          let blockedByCreation = false;
          const deadline = Date.now() + 3_000;
          while (!archiveSettled && Date.now() < deadline) {
            const waiting = await pool.query<{ blocked: boolean }>(
              "select $2::integer=any(pg_blocking_pids($1::integer)) as blocked",
              [archivePid, creationPid]
            );
            if (waiting.rows[0]?.blocked) {
              blockedByCreation = true;
              break;
            }
            await new Promise((resolve) => setTimeout(resolve, 20));
          }
          finishCreation.resolve();
          const created = await creation;
          const archived = await archiveUpdate;
          await archive.query(archived.status === "archived" ? "commit" : "rollback");
          archiveOpen = false;
          const stored = await pool.query<Record<string, string>>(
            `select
               (select state from boards where id=$1) as board_state,
               (select row_version::text from boards where id=$1) as board_version,
               (select count(*)::text from proposals) as proposals,
               (select count(*)::text from secretariat_requests) as requests,
               (select count(*)::text from secretariat_request_turns) as turns,
               (select count(*)::text from idempotency_records) as idempotency,
               (select count(*)::text from audit_events) as audit`,
            [actor.boardId]
          );
          expect({ blockedByCreation, created, archived, stored: stored.rows[0] }).toEqual({
            blockedByCreation: true,
            created: { status: "created", code: "" },
            archived: { status: "archived", code: "" },
            stored: {
              board_state: "archived",
              board_version: "2",
              proposals: operation === "propose_action" ? "1" : "0",
              requests: operation === "ask_secretariat" ? "1" : "0",
              turns: operation === "ask_secretariat" ? "1" : "0",
              idempotency: "1",
              audit: "1"
            }
          });
        } finally {
          finishCreation.resolve();
          try {
            await creation;
            if (archiveUpdate) await archiveUpdate;
            if (archiveOpen) await archive.query("rollback");
          } finally {
            archive.release();
          }
        }
      });
    }
  );

  it("upgrades 164 to 165 preserving communication history, retries, reads and function authority", async () => {
    const migrations = (await loadMigrations(MIGRATIONS)).filter(({ version }) => version <= 165);
    const upgrade = migrations.find(({ version }) => version === 165);
    expect(upgrade?.name).toBe("0165_active_board_communication_creation.sql");
    const scratchRoot = path.resolve(import.meta.dirname, "../../tmp");
    await mkdir(scratchRoot, { recursive: true });
    const directory = await mkdtemp(path.join(scratchRoot, "communications-upgrade-"));
    const baseline = path.join(directory, "schema164");
    const target = path.join(directory, "schema165");
    await mkdir(baseline);
    await mkdir(target);
    let passed = false;
    try {
      for (const migration of migrations) {
        await writeFile(path.join(target, migration.name), migration.sql, { flag: "wx" });
        expect(sha256Hex(await readFile(path.join(target, migration.name)))).toBe(migration.sha256);
        if (migration.version <= 164) {
          await writeFile(path.join(baseline, migration.name), migration.sql, { flag: "wx" });
          expect(sha256Hex(await readFile(path.join(baseline, migration.name)))).toBe(
            migration.sha256
          );
        }
      }
      await withDatabase(async (pool) => {
        const actor = await seedAuthorizedActor(pool, {
          seatRole: "voting_member",
          scopes: ["member:propose", "secretariat:message", "governance:read"]
        });
        const secretary = await seedAdditionalAuthorizedActor(pool, actor, {
          idBase: 1400,
          seatRole: "management",
          scopes: ["secretariat:admin", "secretariat:message", "governance:read"],
          isSecretary: true
        });
        const proposal = proposalInput(actor, 1500, "proposal-before-upgrade-0001");
        const question = askInput(actor, 1600, "request-before-upgrade-0001");
        const proposed = await request(pool, actor, (client) =>
          proposeActionInTransaction(client, proposal)
        );
        const asked = await request(pool, actor, (client) =>
          askSecretariatInTransaction(client, question)
        );
        await pool.query(
          "update boards set state='archived',row_version=row_version+1 where id=$1",
          [actor.boardId]
        );
        const history = async () =>
          (
            await pool.query<{ snapshot: Record<string, unknown> }>(
              `select jsonb_build_object(
             'boards',(select jsonb_agg(to_jsonb(record) order by id) from boards as record),
             'proposals',(select jsonb_agg(to_jsonb(record) order by id) from proposals as record),
             'requests',(select jsonb_agg(to_jsonb(record) order by id) from secretariat_requests as record),
             'turns',(select jsonb_agg(to_jsonb(record) order by id) from secretariat_request_turns as record),
             'idempotency',(select jsonb_agg(to_jsonb(record) order by id) from idempotency_records as record),
             'audit',(select jsonb_agg(to_jsonb(record) order by sequence) from audit_events as record
                where event_type<>'migration_applied')
           ) as snapshot`
            )
          ).rows[0]!.snapshot;
        const catalog = async () =>
          (
            await pool.query<{
              name: string;
              definition: string;
              owner: string;
              acl: string;
              config: string[];
              volatility: string;
              security_definer: boolean;
              signature: string;
              result_type: string;
            }>(
              `select procedure.proname as name,pg_get_functiondef(procedure.oid) as definition,
             owner.rolname as owner,procedure.proacl::text as acl,procedure.proconfig as config,
             procedure.provolatile as volatility,procedure.prosecdef as security_definer,
             procedure.oid::regprocedure::text as signature,
             pg_get_function_result(procedure.oid) as result_type
           from pg_proc as procedure join pg_namespace as namespace on namespace.oid=procedure.pronamespace
           join pg_roles as owner on owner.oid=procedure.proowner
           where namespace.nspname='public' and procedure.proname=any($1::text[])
           order by procedure.proname`,
              [
                [
                  "boardagent_create_proposal",
                  "boardagent_create_secretariat_request",
                  "boardagent_communication_actor_ready",
                  "boardagent_secretariat_for_board",
                  "boardagent_proposer_for_board",
                  "boardagent_proposal_action_authorized",
                  "boardagent_secretariat_request_action_authorized",
                  "boardagent_communication_replay_authorized",
                  "boardagent_guard_communication_root",
                  "boardagent_verify_communication_audit"
                ]
              ]
            )
          ).rows;
        const ledger = async () =>
          (
            await pool.query(
              "select version,name,sha256,applied_at::text,app_build from schema_migrations order by version"
            )
          ).rows;
        const before = await history();
        const beforeCatalog = await catalog();
        const beforeLedger = await ledger();
        expect(beforeLedger).toHaveLength(164);
        expect(beforeCatalog).toHaveLength(10);
        for (const entry of beforeCatalog.filter(({ name }) =>
          name.startsWith("boardagent_create_")
        )) {
          expect(entry).toMatchObject({
            config: ["search_path=pg_catalog, public, pg_temp"],
            owner: "boardagent_migrator",
            security_definer: true,
            volatility: "v"
          });
        }

        await migrate(pool, target, "communications-upgrade-test");
        const afterLedger = await ledger();
        expect(afterLedger).toHaveLength(165);
        expect(afterLedger.slice(0, 164)).toEqual(beforeLedger);
        expect(afterLedger[164]).toMatchObject({
          version: 165,
          name: upgrade!.name,
          sha256: upgrade!.sha256
        });
        const migrationAudit = await pool.query<{ event: unknown }>(
          "select convert_from(canonical_payload,'UTF8')::jsonb as event from audit_events where event_type='migration_applied'"
        );
        expect(migrationAudit.rows).toEqual([
          {
            event: expect.objectContaining({
              eventType: "migration_applied",
              entityId: upgrade!.name,
              details: {
                version: 165,
                name: upgrade!.name,
                sha256: upgrade!.sha256,
                appBuild: "communications-upgrade-test"
              }
            })
          }
        ]);
        expect(await history()).toEqual(before);
        const afterCatalog = await catalog();
        const metadata = (entries: typeof beforeCatalog) =>
          entries.map(({ definition: _definition, ...entry }) => entry);
        expect(metadata(afterCatalog)).toEqual(metadata(beforeCatalog));
        expect(afterCatalog.filter(({ name }) => !name.startsWith("boardagent_create_"))).toEqual(
          beforeCatalog.filter(({ name }) => !name.startsWith("boardagent_create_"))
        );

        expect(
          await request(pool, actor, (client) => proposeActionInTransaction(client, proposal))
        ).toEqual({
          replayed: true,
          operation: "propose_action",
          objectId: proposal.proposalId,
          responseSha256: proposed.responseSha256
        });
        expect(
          await request(pool, actor, (client) => askSecretariatInTransaction(client, question))
        ).toEqual({
          replayed: true,
          operation: "ask_secretariat",
          objectId: question.requestId,
          responseSha256: asked.responseSha256
        });
        const readRows = (reader: AuthorizedActorFixture) =>
          request(pool, reader, async (client) => ({
            proposals: (
              await client.query("select id from proposals where id=$1", [proposal.proposalId])
            ).rows,
            requests: (
              await client.query(
                `select request.id,turn.canonical_text from secretariat_requests as request
               join secretariat_request_turns as turn on turn.request_id=request.id where request.id=$1`,
                [question.requestId]
              )
            ).rows
          }));
        expect(await readRows(secretary)).toEqual({
          proposals: [{ id: proposal.proposalId }],
          requests: [{ id: question.requestId, canonical_text: question.message }]
        });
        expect(await readRows(actor)).toEqual({
          proposals: [],
          requests: [{ id: question.requestId, canonical_text: question.message }]
        });
        await expect(
          request(pool, actor, (client) =>
            proposeActionInTransaction(
              client,
              proposalInput(actor, 1700, "proposal-after-upgrade-0001")
            )
          )
        ).rejects.toThrow(/unavailable/u);
        await expect(
          request(pool, actor, (client) =>
            askSecretariatInTransaction(client, askInput(actor, 1800, "request-after-upgrade-0001"))
          )
        ).rejects.toThrow(/unavailable/u);
        expect(await history()).toEqual(before);
        await pool.query(
          "update access_token_records set revoked_at=transaction_timestamp() where id=$1",
          [actor.accessTokenRecordId]
        );
        await expect(
          request(pool, actor, (client) => proposeActionInTransaction(client, proposal))
        ).rejects.toThrow(/unavailable/u);
        await expect(
          request(pool, actor, (client) => askSecretariatInTransaction(client, question))
        ).rejects.toThrow(/unavailable/u);
        expect(await history()).toEqual(before);
      }, baseline);
      passed = true;
    } finally {
      if (passed) await rm(directory, { recursive: true });
      else process.stderr.write(`Preserved failed communications migration inputs: ${directory}\n`);
    }
  });

  it("stores inert proposals, supports safe replay, and permits only the proposer to withdraw", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["member:propose", "secretariat:message"]
      });
      const other = await seedAdditionalAuthorizedActor(pool, actor, {
        idBase: 100,
        seatRole: "voting_member",
        scopes: ["member:propose", "secretariat:message"]
      });
      const input = proposalInput(actor, 200, "proposal-create-replay-0001");
      const created = await request(pool, actor, (client) =>
        proposeActionInTransaction(client, input)
      );
      expect(created).toMatchObject({
        replayed: false,
        operation: "propose_action",
        objectId: input.proposalId,
        state: "pending",
        rowVersion: 1n
      });

      const replayed = await request(pool, actor, (client) =>
        proposeActionInTransaction(client, {
          ...input,
          idempotencyRecordId: testId(210),
          auditEventId: testId(211)
        })
      );
      expect(replayed).toEqual({
        replayed: true,
        operation: "propose_action",
        objectId: input.proposalId,
        responseSha256: created.responseSha256
      });
      const ownerAuthorization = await request(pool, actor, async (client) => {
        const result = await client.query<{
          action_authorized: boolean;
          actor_ready: boolean;
          proposer_ready: boolean;
        }>(
          `select boardagent_proposal_action_authorized($1,'withdraw_proposal') as action_authorized,
                  boardagent_communication_actor_ready($2,'member:propose') as actor_ready,
                  boardagent_proposer_for_board($2) as proposer_ready`,
          [input.proposalId, actor.boardId]
        );
        return result.rows[0];
      });
      expect(ownerAuthorization).toEqual({
        action_authorized: true,
        actor_ready: true,
        proposer_ready: true
      });
      await expect(
        request(pool, other, (client) =>
          withdrawProposalInTransaction(client, {
            organizationId: actor.organizationId,
            proposalId: input.proposalId,
            idempotencyRecordId: testId(212),
            idempotencyKey: "proposal-wrong-owner-0001",
            auditEventId: testId(213)
          })
        )
      ).rejects.toThrow(/unavailable/u);
      const withdrawn = await request(pool, actor, (client) =>
        withdrawProposalInTransaction(client, {
          organizationId: actor.organizationId,
          proposalId: input.proposalId,
          idempotencyRecordId: testId(214),
          idempotencyKey: "proposal-owner-withdraw-0001",
          auditEventId: testId(215)
        })
      );
      expect(withdrawn).toMatchObject({ state: "withdrawn", rowVersion: 2n });
      expect(
        await request(pool, actor, (client) =>
          withdrawProposalInTransaction(client, {
            organizationId: actor.organizationId,
            proposalId: input.proposalId,
            idempotencyRecordId: testId(299),
            idempotencyKey: "proposal-owner-withdraw-0001",
            auditEventId: testId(298)
          })
        )
      ).toMatchObject({ replayed: true, objectId: input.proposalId });
      expect(
        await request(
          pool,
          actor,
          async (client) =>
            (await client.query("select id from proposals where id=$1", [input.proposalId])).rows
        )
      ).toEqual([]);
      await expect(
        request(pool, other, (client) =>
          withdrawProposalInTransaction(client, {
            organizationId: actor.organizationId,
            proposalId: input.proposalId,
            idempotencyRecordId: testId(297),
            idempotencyKey: "proposal-owner-withdraw-0001",
            auditEventId: testId(296)
          })
        )
      ).rejects.toThrow(/unavailable/u);
      const stored = await pool.query<{
        audit_types: string[];
        idempotency_count: string;
        state: string;
      }>(
        `select proposal.state,
                (select array_agg(event_type order by sequence) from audit_events) as audit_types,
                (select count(*)::text from idempotency_records) as idempotency_count
           from proposals as proposal where proposal.id=$1`,
        [input.proposalId]
      );
      expect(stored.rows[0]).toEqual({
        state: "withdrawn",
        audit_types: ["proposal_submitted", "proposal_withdrawn"],
        idempotency_count: "2"
      });
    });
  });

  it("serializes competing secretary dispositions and approval creates only an inert draft", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["member:propose", "secretariat:message"]
      });
      const secretary = await seedAdditionalAuthorizedActor(pool, actor, {
        idBase: 300,
        seatRole: "voting_member",
        scopes: ["secretariat:admin", "secretariat:message"],
        isSecretary: true
      });
      const proposal = proposalInput(actor, 400, "proposal-for-disposition-0001");
      await request(pool, actor, (client) => proposeActionInTransaction(client, proposal));
      const signedContext = Buffer.from(
        '{"schemaVersion":"boardagent.proposal-draft-context.v1","reviewed":true}',
        "utf8"
      );
      const approval: ApproveProposalInput = {
        organizationId: actor.organizationId,
        dispositionId: testId(410),
        proposalId: proposal.proposalId,
        resultingDraftId: testId(411),
        draftType: "meeting",
        signedContext,
        contextSha256: sha256Hex(signedContext),
        idempotencyRecordId: testId(412),
        idempotencyKey: "proposal-approve-race-0001",
        auditEventId: testId(413)
      };
      const rejection = {
        organizationId: actor.organizationId,
        dispositionId: testId(420),
        proposalId: proposal.proposalId,
        reason: "The requested timing is not workable.",
        idempotencyRecordId: testId(421),
        idempotencyKey: "proposal-reject-race-0001",
        auditEventId: testId(422)
      };
      const outcomes = await Promise.allSettled([
        request(pool, secretary, (client) => approveProposalInTransaction(client, approval)),
        request(pool, secretary, (client) => rejectProposalInTransaction(client, rejection))
      ]);
      expect(outcomes.filter(({ status }) => status === "fulfilled")).toHaveLength(1);
      expect(outcomes.filter(({ status }) => status === "rejected")).toHaveLength(1);
      const approvedWon = outcomes[0]!.status === "fulfilled";
      expect(
        await request(pool, secretary, (client) =>
          approvedWon
            ? approveProposalInTransaction(client, approval)
            : rejectProposalInTransaction(client, rejection)
        )
      ).toMatchObject({ replayed: true, objectId: proposal.proposalId });
      await expect(
        request(pool, secretary, (client) =>
          approvedWon
            ? approveProposalInTransaction(client, { ...approval, draftType: "vote" })
            : rejectProposalInTransaction(client, { ...rejection, reason: "Changed reason" })
        )
      ).rejects.toThrow(/different communication request/);
      await expect(
        request(pool, actor, (client) =>
          approvedWon
            ? approveProposalInTransaction(client, approval)
            : rejectProposalInTransaction(client, rejection)
        )
      ).rejects.toThrow(/unavailable/);
      const stored = await pool.query<{
        disposition_count: string;
        draft_count: string;
        state: string;
      }>(
        `select proposal.state,
                (select count(*)::text from proposal_dispositions
                  where proposal_id=proposal.id) as disposition_count,
                (select count(*)::text from wizard_drafts
                  where id=$2 and state='active' and current_step=0 and package_sha256 is null)
                  as draft_count
           from proposals as proposal where proposal.id=$1`,
        [proposal.proposalId, approval.resultingDraftId]
      );
      expect(stored.rows[0]?.disposition_count).toBe("1");
      if (stored.rows[0]?.state === "approved_to_draft") {
        expect(stored.rows[0]?.draft_count).toBe("1");
      } else {
        expect(stored.rows[0]).toMatchObject({ state: "rejected", draft_count: "0" });
      }
    });
  });

  it("records an immutable request/reply/close thread with exact role boundaries", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "management",
        scopes: ["secretariat:message"]
      });
      const secretary = await seedAdditionalAuthorizedActor(pool, actor, {
        idBase: 500,
        seatRole: "voting_member",
        scopes: ["secretariat:admin", "secretariat:message"],
        isSecretary: true
      });
      const input = askInput(actor, 600, "secretariat-ask-thread-0001");
      const created = await request(pool, actor, (client) =>
        askSecretariatInTransaction(client, input)
      );
      expect(created).toMatchObject({ state: "open", rowVersion: 1n });
      await expect(
        request(pool, actor, (client) =>
          replySecretariatRequestInTransaction(client, {
            organizationId: actor.organizationId,
            requestId: input.requestId,
            turnId: testId(610),
            reply: "Actor must not answer the secretariat thread.",
            idempotencyRecordId: testId(611),
            idempotencyKey: "secretariat-wrong-reply-0001",
            auditEventId: testId(612)
          })
        )
      ).rejects.toThrow(/unavailable/u);
      const replied = await request(pool, secretary, (client) =>
        replySecretariatRequestInTransaction(client, {
          organizationId: actor.organizationId,
          requestId: input.requestId,
          turnId: testId(620),
          reply: "The proposed date is 15 September at 10:00 UTC.",
          idempotencyRecordId: testId(621),
          idempotencyKey: "secretariat-valid-reply-0001",
          auditEventId: testId(622)
        })
      );
      expect(replied).toMatchObject({ state: "answered", rowVersion: 2n });
      const closed = await request(pool, actor, (client) =>
        closeSecretariatRequestInTransaction(client, {
          organizationId: actor.organizationId,
          requestId: input.requestId,
          idempotencyRecordId: testId(630),
          idempotencyKey: "secretariat-request-close-0001",
          auditEventId: testId(631)
        })
      );
      expect(closed).toMatchObject({ state: "closed", rowVersion: 3n });
      expect(
        await request(pool, actor, (client) =>
          closeSecretariatRequestInTransaction(client, {
            organizationId: actor.organizationId,
            requestId: input.requestId,
            idempotencyRecordId: testId(639),
            idempotencyKey: "secretariat-request-close-0001",
            auditEventId: testId(638)
          })
        )
      ).toMatchObject({ replayed: true, objectId: input.requestId });
      const stored = await pool.query<{
        audit_types: string[];
        state: string;
        turn_kinds: string[];
      }>(
        `select request.state,
                (select array_agg(turn_kind order by ordinal)
                   from secretariat_request_turns where request_id=request.id) as turn_kinds,
                (select array_agg(event_type order by sequence) from audit_events) as audit_types
           from secretariat_requests as request where request.id=$1`,
        [input.requestId]
      );
      expect(stored.rows[0]).toEqual({
        state: "closed",
        turn_kinds: ["request", "reply"],
        audit_types: [
          "secretariat_request_created",
          "secretariat_request_replied",
          "secretariat_request_closed"
        ]
      });
      await expect(
        pool.query(
          "update secretariat_request_turns set canonical_text='tampered' where request_id=$1",
          [input.requestId]
        )
      ).rejects.toThrow(/immutable evidence/u);
    });
  });

  it("rolls back the entire proposal when the final audit append fails", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["member:propose"]
      });
      const first = proposalInput(actor, 700, "proposal-audit-first-0001");
      await request(pool, actor, (client) => proposeActionInTransaction(client, first));
      const failing = {
        ...proposalInput(actor, 710, "proposal-audit-failure-0001"),
        auditEventId: first.auditEventId
      };
      await expect(
        request(pool, actor, (client) => proposeActionInTransaction(client, failing))
      ).rejects.toThrow();
      const readback = await pool.query<{ idempotency_count: string; proposal_count: string }>(
        `select
           (select count(*)::text from proposals where id=$1) as proposal_count,
           (select count(*)::text from idempotency_records where id=$2) as idempotency_count`,
        [failing.proposalId, failing.idempotencyRecordId]
      );
      expect(readback.rows[0]).toEqual({ proposal_count: "0", idempotency_count: "0" });
    });
  });
});
