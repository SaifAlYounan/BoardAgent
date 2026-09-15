import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { Pool, type PoolClient } from "pg";

import { type SurfacePrincipal, type SurfaceToolResult } from "../../artifacts/server/src/index.js";
import { DirectReadRepository } from "../helpers/direct-response-allocation.js";
import { TOOL_INPUT_SCHEMA_VERSION, type JsonValue } from "../../lib/contracts/src/index.js";
import {
  appendAuditEventsInTransaction,
  confirmStagedActionInTransaction,
  migrate,
  stageActionInTransaction,
  withRequestTransaction,
  type RequestDatabaseContext,
  type StageActionInput
} from "../../lib/db/src/index.js";
import {
  seedAuthorizedActor,
  testHash,
  testId,
  type AuthorizedActorFixture
} from "../../tests/helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";

export const ENVELOPE = Object.freeze({
  organizations: 1,
  boards: 25,
  seats: 1_000,
  concurrentMcpRequests: 100,
  documentVersions: 100_000,
  auditEvents: 1_000_000,
  feedEvents: 1_000_000,
  maximumDocumentBytes: 10 * 1024 * 1024,
  briefingItems: 1_000
});

const TARGETS_MS = Object.freeze({
  warmList: 500,
  warmGet: 500,
  entitledSearch: 1_500,
  briefing: 1_500,
  consentServer: 750,
  auditAppend: 250
});

const SERVER_TRANSACTION = Object.freeze({
  assumeRole: "boardagent_server" as const,
  lockTimeoutMs: 10_000,
  statementTimeoutMs: 30_000
});

interface Metric {
  readonly name: string;
  readonly samples: number;
  readonly p95Ms: number;
  readonly maximumMs: number;
  readonly targetMs: number;
}

export interface FixtureCounts {
  readonly organizations: string;
  readonly boards: string;
  readonly seats: string;
  readonly document_versions: string;
  readonly audit_events: string;
  readonly audit_checkpoints: string;
  readonly feed_events: string;
  readonly feed_sync_positions: string;
  readonly feed_sync_counters: string;
  readonly invalid_feed_sync_rows: string;
  readonly maximum_document_bytes: string;
}

interface TokenResolution {
  readonly token_record_id: string;
  readonly organization_id: string;
  readonly member_id: string;
  readonly internal_client_id: string;
  readonly protocol_client_id: string;
  readonly resource_uri: string;
  readonly scope_set: string[];
  readonly signing_key_kid: string;
  readonly roles: string[];
  readonly board_ids: string[];
}

export interface CapacityFixture {
  readonly actor: AuthorizedActorFixture;
  readonly boardIds: readonly string[];
  readonly noiseMemberIds: readonly string[];
  readonly visibleDocumentIds: readonly string[];
  readonly visibleVersionIds: readonly string[];
}

function roundMilliseconds(value: number): number {
  return Math.round(value * 100) / 100;
}

function percentile95(values: readonly number[]): number {
  assert(values.length > 0, "p95 requires at least one sample");
  const sorted = [...values].toSorted((left, right) => left - right);
  return sorted[Math.ceil(sorted.length * 0.95) - 1] as number;
}

async function measure(
  name: string,
  samples: number,
  targetMs: number,
  run: (sample: number) => Promise<void>,
  warmups = 3
): Promise<Metric> {
  for (let sample = 0; sample < warmups; sample += 1) await run(-sample - 1);
  const durations: number[] = [];
  for (let sample = 0; sample < samples; sample += 1) {
    const started = performance.now();
    await run(sample);
    durations.push(performance.now() - started);
  }
  const rawP95 = percentile95(durations);
  assert(
    rawP95 <= targetMs,
    `${name} p95 ${roundMilliseconds(rawP95).toFixed(2)}ms exceeds ${String(targetMs)}ms`
  );
  return {
    name,
    samples,
    p95Ms: roundMilliseconds(rawP95),
    maximumMs: roundMilliseconds(Math.max(...durations)),
    targetMs
  };
}

function record(value: JsonValue): Readonly<Record<string, JsonValue>> {
  assert(value !== null && !Array.isArray(value) && typeof value === "object");
  return value as Readonly<Record<string, JsonValue>>;
}

function array(value: JsonValue | undefined): readonly JsonValue[] {
  assert(Array.isArray(value));
  return value;
}

function assertPage(result: SurfaceToolResult, minimumItems = 1): void {
  assert.equal(result.status, "ok");
  const items = array(record(result.data)["items"]);
  assert(items.length >= minimumItems);
  assert(items.length <= 500);
}

function assertDocumentHash(
  result: SurfaceToolResult,
  documentId: string,
  versionId: string
): void {
  assert.equal(result.status, "ok");
  assert.equal(result.reference, versionId);
  const found = record(record(result.data)["document_hash"] as JsonValue);
  assert.equal(found["document_id"], documentId);
  assert.equal(found["version_id"], versionId);
}

function assertBriefing(result: SurfaceToolResult): void {
  assert.equal(result.status, "ok");
  const data = record(result.data);
  assert.equal(data["status"], "complete");
  assert.equal(array(data["items"]).length, ENVELOPE.briefingItems);
  assert.equal(typeof data["next_cursor"], "string");
}

function assertEmptySearch(result: SurfaceToolResult): void {
  assert.equal(result.status, "ok");
  assert.equal(array(record(result.data)["items"]).length, 0);
}

async function withDisposableDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  const database = `boardagent_perf_${String(process.pid)}_${Date.now().toString(36)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const ownerUrl = new URL(BASE_URL);
  ownerUrl.pathname = `/${database}`;
  // The 100-way concurrent burst queues on these 40 clients; its p95 is reported, not
  // targeted (14.2 s on a 2-CPU host). A 10 s acquire wait therefore aborted the whole
  // run on that host before any of the six frozen targets was measured. The wait bound is harness plumbing: 60 s lets the
  // burst complete and be reported honestly; every TARGETS_MS assertion is unchanged.
  const owner = new Pool({
    connectionString: ownerUrl.toString(),
    max: 40,
    connectionTimeoutMillis: 60_000
  });
  const poolState: { cleanupStarted: boolean; unexpectedError: Error | null } = {
    cleanupStarted: false,
    unexpectedError: null
  };
  owner.on("error", (error) => {
    if (!poolState.cleanupStarted) poolState.unexpectedError = error;
  });
  try {
    await migrate(owner, MIGRATIONS, "phase1-performance");
    const result = await run(owner);
    if (poolState.unexpectedError) throw poolState.unexpectedError;
    return result;
  } finally {
    poolState.cleanupStarted = true;
    await owner.end();
    await admin.query(`drop database "${database}"`);
    await admin.end();
  }
}

async function inBulkFixtureTransaction(
  pool: Pool,
  run: (client: PoolClient) => Promise<void>
): Promise<void> {
  const client = await pool.connect();
  let open = false;
  try {
    await client.query("begin");
    open = true;
    await client.query("set local synchronous_commit=off");
    await run(client);
    await client.query("commit");
    open = false;
  } catch (error) {
    if (open) await client.query("rollback").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

async function seedBoardsAndSeats(
  pool: Pool,
  actor: AuthorizedActorFixture
): Promise<{ readonly boardIds: readonly string[]; readonly noiseMemberIds: readonly string[] }> {
  const extraBoardIds = Array.from({ length: ENVELOPE.boards - 1 }, (_, index) =>
    testId(1_001 + index)
  );
  const supportIds = extraBoardIds.map((_, index) => testId(2_001 + index));
  const membershipIds = extraBoardIds.map((_, index) => testId(3_001 + index));
  const attestationIds = extraBoardIds.map((_, index) => testId(4_001 + index));
  const boardIds = [actor.boardId, ...extraBoardIds].toSorted();

  await pool.query(
    `insert into boards(id,organization_id,slug,name,timezone)
     select fixture.board_id,$1,'benchmark-board-' || fixture.ordinality::text,
            'Benchmark board ' || fixture.ordinality::text,'UTC'
       from unnest($2::uuid[]) with ordinality as fixture(board_id,ordinality)`,
    [actor.organizationId, extraBoardIds]
  );
  await pool.query(
    `insert into secretary_support_versions(
       id,organization_id,board_id,version,support_name,contact_methods,canonical_sha256,
       effective_at,created_by
     )
     select fixture.support_id,$1,fixture.board_id,1,'Board secretary','[]'::jsonb,
            decode(repeat('21',32),'hex'),transaction_timestamp()-interval '1 minute',$2
       from unnest($3::uuid[],$4::uuid[]) as fixture(board_id,support_id)`,
    [actor.organizationId, actor.memberId, extraBoardIds, supportIds]
  );
  await pool.query(
    `insert into board_memberships(
       id,organization_id,board_id,member_id,seat_role,is_secretary,voting_weight,state
     )
     select fixture.membership_id,$1,fixture.board_id,$2,'voting_member',false,1,'active'
       from unnest($3::uuid[],$4::uuid[]) as fixture(board_id,membership_id)`,
    [actor.organizationId, actor.memberId, extraBoardIds, membershipIds]
  );
  await pool.query(
    `insert into onboarding_attestations(
       id,organization_id,member_id,board_id,terms_version_id,support_version_id,
       presentation_choice,local_memory_choice,consent_record_id
     )
     select fixture.attestation_id,$1,$2,fixture.board_id,$3,fixture.support_id,
            'structured','local-only',$4
       from unnest($5::uuid[],$6::uuid[],$7::uuid[]) as
            fixture(board_id,support_id,attestation_id)`,
    [
      actor.organizationId,
      actor.memberId,
      testId(6),
      actor.consentRecordId,
      extraBoardIds,
      supportIds,
      attestationIds
    ]
  );

  const noiseSeatCount = ENVELOPE.seats - ENVELOPE.boards;
  const noiseMemberIds = Array.from({ length: noiseSeatCount }, (_, index) =>
    testId(10_001 + index)
  );
  const noiseMembershipIds = noiseMemberIds.map((_, index) => testId(20_001 + index));
  const noiseBoardIds = noiseMemberIds.map(
    (_, index) => boardIds[index % boardIds.length] as string
  );
  await pool.query(
    `insert into members(id,organization_id,member_kind,legal_name,display_name,state)
     select fixture.member_id,$1,'human','Benchmark member ' || fixture.ordinality::text,
            'Benchmark member ' || fixture.ordinality::text,'active'
       from unnest($2::uuid[]) with ordinality as fixture(member_id,ordinality)`,
    [actor.organizationId, noiseMemberIds]
  );
  await pool.query(
    `insert into board_memberships(
       id,organization_id,board_id,member_id,seat_role,is_secretary,voting_weight,state
     )
     select fixture.membership_id,$1,fixture.board_id,fixture.member_id,
            'voting_member',false,1,'active'
       from unnest($2::uuid[],$3::uuid[],$4::uuid[]) as
            fixture(membership_id,board_id,member_id)`,
    [actor.organizationId, noiseMembershipIds, noiseBoardIds, noiseMemberIds]
  );
  return { boardIds, noiseMemberIds };
}

async function seedDocuments(
  pool: Pool,
  actor: AuthorizedActorFixture,
  boardIds: readonly string[],
  noiseMemberIds: readonly string[]
): Promise<{
  readonly visibleDocumentIds: readonly string[];
  readonly visibleVersionIds: readonly string[];
}> {
  const hiddenCreators = boardIds.map((_, index) => noiseMemberIds[index] as string);
  await inBulkFixtureTransaction(pool, async (client) => {
    await client.query("set constraints documents_current_version_fk deferred");
    await client.query(
      `with fixture as (
         select series.i,
                ($1::uuid[])[((series.i-1)%$2)+1] as board_id,
                case when series.i%200=0
                     then ($3::uuid[])[((series.i-1)%$2)+1]
                     else $4::uuid end as creator_id,
                ('018f0000-0000-7000-8000-' ||
                  lpad(to_hex(1000000+series.i),12,'0'))::uuid as document_id,
                ('018f0000-0000-7000-8000-' ||
                  lpad(to_hex(2000000+series.i),12,'0'))::uuid as version_id
           from generate_series(1,$5::integer) as series(i)
       )
       insert into documents(
         id,organization_id,board_id,title,current_version_id,created_by,created_at
       )
       select document_id,$6,board_id,'Benchmark document ' || i::text,version_id,creator_id,
              timestamptz '2026-01-02 00:00:00+00' + i*interval '1 microsecond'
         from fixture`,
      [
        [...boardIds],
        ENVELOPE.boards,
        hiddenCreators,
        actor.memberId,
        ENVELOPE.documentVersions,
        actor.organizationId
      ]
    );
    await client.query(
      `with fixture as (
         select series.i,
                ($1::uuid[])[((series.i-1)%$2)+1] as board_id,
                case when series.i%200=0
                     then ($3::uuid[])[((series.i-1)%$2)+1]
                     else $4::uuid end as creator_id,
                ('018f0000-0000-7000-8000-' ||
                  lpad(to_hex(1000000+series.i),12,'0'))::uuid as document_id,
                ('018f0000-0000-7000-8000-' ||
                  lpad(to_hex(2000000+series.i),12,'0'))::uuid as version_id,
                case when series.i=2 then convert_to(repeat('x',$5),'UTF8')
                     else convert_to('benchmark-' || series.i::text,'UTF8') end as content
           from generate_series(1,$6::integer) as series(i)
       )
       insert into document_versions(
         id,organization_id,board_id,document_id,version,media_type,document_schema,
         canonicalization_version,canonical_bytes,byte_length,sha256,canonical_metadata,
         created_by,created_at
       )
       select version_id,$7,board_id,document_id,1,'text/plain; charset=utf-8',null,
              'RFC8785+NFC-LF-v1',content,octet_length(content),
              decode(lpad(to_hex(2000000+i),64,'0'),'hex'),'{"fixture":true}'::jsonb,
              creator_id,timestamptz '2026-01-02 00:00:00+00' + i*interval '1 microsecond'
         from fixture`,
      [
        [...boardIds],
        ENVELOPE.boards,
        hiddenCreators,
        actor.memberId,
        ENVELOPE.maximumDocumentBytes,
        ENVELOPE.documentVersions,
        actor.organizationId
      ]
    );
    await client.query(
      `with fixture as (
         select series.i,
                ($1::uuid[])[((series.i-1)%$2)+1] as board_id,
                ('018f0000-0000-7000-8000-' ||
                  lpad(to_hex(1000000+series.i),12,'0'))::uuid as document_id,
                ('018f0000-0000-7000-8000-' ||
                  lpad(to_hex(2000000+series.i),12,'0'))::uuid as version_id
           from generate_series(1,$3::integer) as series(i)
       )
       insert into document_search(
         document_id,board_id,current_version_id,canonical_text_sha256,search_text,indexed_at
       )
       select document_id,board_id,version_id,
              decode(lpad(to_hex(2000000+i),64,'0'),'hex'),
              case when i%200=0 then 'restrictedneedle hidden fixture ' || i::text
                   when i%97=0 then 'needle visible fixture ' || i::text
                   else 'visible fixture document ' || i::text end,
              timestamptz '2026-01-02 00:00:00+00' + i*interval '1 microsecond'
         from fixture`,
      [[...boardIds], ENVELOPE.boards, ENVELOPE.documentVersions]
    );
  });
  return {
    visibleDocumentIds: boardIds.map((_, index) => testId(1_000_001 + index)),
    visibleVersionIds: boardIds.map((_, index) => testId(2_000_001 + index))
  };
}

/**
 * These rows are a disposable statistics fixture, not evidentiary data. Their sequence,
 * foreign-key and index shapes are representative, but their hashes are deliberately not
 * recomputed through the production canonical audit kernel. The benchmark never runs the
 * chain verifier against this database and never exports this database as proof.
 */
async function seedStatisticalAuditRows(
  pool: Pool,
  actor: AuthorizedActorFixture,
  boardIds: readonly string[]
): Promise<void> {
  await inBulkFixtureTransaction(pool, async (client) => {
    await client.query("set local session_replication_role=replica");
    await client.query(
      `insert into audit_events(
         id,sequence,organization_id,board_id,event_type,schema_version,actor_member_id,
         client_id,token_jti,object_type,object_id,object_version,canonical_payload,
         previous_event_sha256,event_sha256,occurred_at
       )
       select ('018f0000-0000-7000-8000-' ||
                 lpad(to_hex(3000000+series.i),12,'0'))::uuid,
              series.i,$1,($2::uuid[])[((series.i-1)%$3)+1],
              'context_read','boardagent.audit-event.v1',$4,$5,$6,
              'performance_fixture',
              ('018f0000-0000-7000-8000-' ||
                 lpad(to_hex(1000000+((series.i-1)%$7)+1),12,'0'))::uuid,
              1,convert_to('{}','UTF8'),
              case when series.i=1 then decode(repeat('00',32),'hex')
                   else decode(lpad(to_hex(series.i-1),64,'0'),'hex') end,
              decode(lpad(to_hex(series.i),64,'0'),'hex'),
              timestamptz '2026-01-03 00:00:00+00' + series.i*interval '1 microsecond'
         from generate_series(1,$8::integer) as series(i)`,
      [
        actor.organizationId,
        [...boardIds],
        ENVELOPE.boards,
        actor.memberId,
        actor.clientId,
        actor.tokenJti,
        ENVELOPE.documentVersions,
        ENVELOPE.auditEvents
      ]
    );
    await client.query(
      `update audit_chain_head
          set last_sequence=$1,
              last_event_sha256=decode(lpad(to_hex($1::bigint),64,'0'),'hex'),
              row_version=row_version+1
        where singleton_key`,
      [ENVELOPE.auditEvents]
    );
    // Model a retained, already checkpointed statistical history. These rows are NOT
    // signatures/evidence: the manifests are labelled and signature bytes are placeholders.
    // Bulk fixture construction ends with this transaction; measured appends still execute
    // the real capacity guard. The MCP load fixture registers real active keys before
    // this retained history is added; runtime startup must never bypass key succession.
    const historyKeyId = testId(7_600_000);
    await client.query(
      `insert into crypto_key_registry(id,organization_id,kid,purpose,algorithm,public_jwk,
         nonsecret_locator,activated_at,retired_at)
       values($1,$2,'statistical-history-only','evidence_signing','EdDSA',$3,
         'synthetic-statistical-history-not-evidence','2026-01-01T00:00:00Z','2026-01-04T00:00:00Z')`,
      [
        historyKeyId,
        actor.organizationId,
        generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" })
      ]
    );
    await client.query(
      `insert into audit_checkpoints(id,organization_id,first_sequence,last_sequence,
         first_event_sha256,last_event_sha256,canonical_manifest,manifest_sha256,
         signature,signing_key_id,created_at)
       select ('018f0000-0000-7000-8000-'||lpad(to_hex(7600000+series.i),12,'0'))::uuid,
         $1,(series.i-1)*1000+1,least(series.i*1000,$2::integer),
         decode(lpad(to_hex((series.i-1)*1000+1),64,'0'),'hex'),
         decode(lpad(to_hex(least(series.i*1000,$2::integer)),64,'0'),'hex'),
         fixture.bytes,sha256(fixture.bytes),decode(repeat('00',64),'hex'),$3,
         timestamptz '2026-01-03 00:01:00+00'+series.i*interval '1 microsecond'
       from generate_series(1,ceil($2::numeric/1000)::integer) as series(i)
       cross join lateral (select convert_to(
         '{"statisticalFixtureOnly":true,"ordinal":'||series.i::text||'}','UTF8') as bytes) as fixture`,
      [actor.organizationId, ENVELOPE.auditEvents, historyKeyId]
    );
  });
}

async function seedStatisticalFeedRows(
  pool: Pool,
  actor: AuthorizedActorFixture,
  boardIds: readonly string[],
  noiseMemberIds: readonly string[]
): Promise<void> {
  const noiseBoardIds = noiseMemberIds.map(
    (_, index) => boardIds[index % boardIds.length] as string
  );
  await inBulkFixtureTransaction(pool, async (client) => {
    await client.query("set local session_replication_role=replica");
    await client.query(
      `with fixture as (
         select series.i,
                case when series.i<=$1 then $2::uuid
                     else ($3::uuid[])[((series.i-$1-1)%$4)+1] end as member_id,
                case when series.i<=$1
                     then ($5::uuid[])[((series.i-1)%$6)+1]
                     else ($7::uuid[])[((series.i-$1-1)%$4)+1] end as board_id,
                case when series.i<=$1 then series.i::bigint
                     else ((series.i-$1-1)/$4+1)::bigint end as feed_sequence
           from generate_series(1,$8::integer) as series(i)
       )
       insert into pending_action_feed(
         id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
         action_type,object_type,object_id,object_version,visibility_sha256,
         canonical_payload,payload_sha256,state,audit_event_id,created_at
       )
       select ('018f0000-0000-7000-8000-' ||
                 lpad(to_hex(5000000+i),12,'0'))::uuid,
              $9,board_id,member_id,1,feed_sequence,'review_fixture','document',
              ('018f0000-0000-7000-8000-' ||
                 lpad(to_hex(1000000+((i-1)%$10)+1),12,'0'))::uuid,
              1,decode(repeat('31',32),'hex'),convert_to('{}','UTF8'),
              decode(repeat('32',32),'hex'),'pending',$11,
              timestamptz '2026-01-04 00:00:00+00' + i*interval '1 microsecond'
         from fixture`,
      [
        ENVELOPE.briefingItems,
        actor.memberId,
        [...noiseMemberIds],
        noiseMemberIds.length,
        [...boardIds],
        ENVELOPE.boards,
        noiseBoardIds,
        ENVELOPE.feedEvents,
        actor.organizationId,
        ENVELOPE.documentVersions,
        testId(3_000_001)
      ]
    );
    // Replica mode deliberately bypasses evidentiary triggers for this statistical
    // fixture. Supply the derived cursor shape too; measured reads still run the real
    // RLS reader, and ordinary production writes keep using the transaction trigger.
    await client.query(
      `insert into member_feed_sync_positions(
         organization_id,board_id,member_id,entry_kind,entry_id,feed_id,change_sequence
       )
       select organization_id,board_id,member_id,'feed',id,id,feed_sequence
         from pending_action_feed`
    );
    await client.query(
      `insert into member_feed_sync_counters(organization_id,member_id,last_sequence)
       select organization_id,member_id,max(change_sequence)
         from member_feed_sync_positions group by organization_id,member_id`
    );
  });
}

export async function seedCapacityFixture(
  pool: Pool,
  beforeStatisticalHistory?: (actor: AuthorizedActorFixture) => Promise<void>
): Promise<CapacityFixture> {
  process.stdout.write("phase1-performance: seed identity and exact board/seat envelope\n");
  const actor = await seedAuthorizedActor(pool, {
    seatRole: "voting_member",
    scopes: ["governance:read", "onboarding:read", "documents:read", "secretariat:admin"],
    isSecretary: true
  });
  const { boardIds, noiseMemberIds } = await seedBoardsAndSeats(pool, actor);
  await beforeStatisticalHistory?.(actor);
  process.stdout.write("phase1-performance: seed 100,000 document versions\n");
  const { visibleDocumentIds, visibleVersionIds } = await seedDocuments(
    pool,
    actor,
    boardIds,
    noiseMemberIds
  );
  process.stdout.write("phase1-performance: seed 1,000,000 statistical audit rows\n");
  await seedStatisticalAuditRows(pool, actor, boardIds);
  process.stdout.write("phase1-performance: seed 1,000,000 statistical feed rows\n");
  await seedStatisticalFeedRows(pool, actor, boardIds, noiseMemberIds);
  process.stdout.write("phase1-performance: analyze representative statistics\n");
  await pool.query(
    `analyze organizations,boards,members,board_memberships,onboarding_attestations,
             documents,document_versions,document_search,audit_events,audit_checkpoints,pending_action_feed,
             member_feed_sync_positions,member_feed_sync_counters`
  );
  return { actor, boardIds, noiseMemberIds, visibleDocumentIds, visibleVersionIds };
}

export async function readAndAssertFixtureCounts(pool: Pool): Promise<FixtureCounts> {
  const result = await pool.query<FixtureCounts>(
    `select (select count(*) from organizations)::text as organizations,
            (select count(*) from boards)::text as boards,
            (select count(*) from board_memberships)::text as seats,
            (select count(*) from document_versions)::text as document_versions,
            (select count(*) from audit_events)::text as audit_events,
            (select count(*) from audit_checkpoints)::text as audit_checkpoints,
            (select count(*) from pending_action_feed)::text as feed_events,
            (select count(*) from member_feed_sync_positions)::text as feed_sync_positions,
            (select count(*) from member_feed_sync_counters)::text as feed_sync_counters,
            (select count(*) from pending_action_feed as feed
               left join member_feed_sync_positions as position
                 on position.entry_kind='feed' and position.entry_id=feed.id
               left join member_feed_sync_counters as counter
                 on counter.organization_id=feed.organization_id and counter.member_id=feed.member_id
              where position.feed_id is distinct from feed.id
                 or position.organization_id is distinct from feed.organization_id
                 or position.board_id is distinct from feed.board_id
                 or position.member_id is distinct from feed.member_id
                 or position.change_sequence is distinct from feed.feed_sequence
                 or counter.last_sequence is null
                 or counter.last_sequence<position.change_sequence)::text as invalid_feed_sync_rows,
            (select max(byte_length) from document_versions)::text as maximum_document_bytes`
  );
  const counts = result.rows[0];
  assert(counts);
  assert.deepEqual(counts, {
    organizations: String(ENVELOPE.organizations),
    boards: String(ENVELOPE.boards),
    seats: String(ENVELOPE.seats),
    document_versions: String(ENVELOPE.documentVersions),
    audit_events: String(ENVELOPE.auditEvents),
    audit_checkpoints: String(Math.ceil(ENVELOPE.auditEvents / 1000)),
    feed_events: String(ENVELOPE.feedEvents),
    feed_sync_positions: String(ENVELOPE.feedEvents),
    feed_sync_counters: String(ENVELOPE.seats - ENVELOPE.boards + 1),
    invalid_feed_sync_rows: "0",
    maximum_document_bytes: String(ENVELOPE.maximumDocumentBytes)
  });
  return counts;
}

async function createPrincipal(
  pool: Pool,
  actor: AuthorizedActorFixture
): Promise<{ readonly principal: SurfacePrincipal; readonly context: RequestDatabaseContext }> {
  const sessionId = testId(6_001);
  await pool.query(
    `insert into auth_sessions(
       id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,
       expires_at,last_authenticated_at
     ) values ($1,$2,$3,$4,$5,'authenticated','https://boardagent.test',
               transaction_timestamp()+interval '15 minutes',transaction_timestamp())`,
    [sessionId, actor.organizationId, testHash(201), actor.memberId, actor.clientId]
  );
  await pool.query(
    `update access_token_records
        set session_id=$1,expires_at=issued_at+interval '15 minutes'
      where id=$2`,
    [sessionId, actor.accessTokenRecordId]
  );
  const resolved = await pool.query<TokenResolution>(
    "select * from boardagent_resolve_access_token($1)",
    [actor.tokenJti]
  );
  const row = resolved.rows[0];
  assert(row && resolved.rows.length === 1);
  assert.equal(row.board_ids.length, ENVELOPE.boards);
  const principal: SurfacePrincipal = {
    organizationId: row.organization_id,
    memberId: row.member_id,
    serviceOrigin: new URL(row.resource_uri).origin,
    clientId: row.internal_client_id,
    protocolClientId: row.protocol_client_id,
    accessTokenRecordId: row.token_record_id,
    tokenJti: actor.tokenJti,
    keyId: row.signing_key_kid,
    scopes: row.scope_set,
    roles: row.roles,
    boardIds: row.board_ids
  };
  return {
    principal,
    context: {
      organizationId: principal.organizationId,
      memberId: principal.memberId,
      clientId: principal.clientId,
      tokenJti: principal.tokenJti,
      boardIds: principal.boardIds
    }
  };
}

function surfaceInput(fields: Readonly<Record<string, JsonValue>>): JsonValue {
  return { schema_version: TOOL_INPUT_SCHEMA_VERSION, ...fields };
}

async function readAuditHead(pool: Pool): Promise<string> {
  const result = await pool.query<{ last_sequence: string }>(
    "select last_sequence::text from audit_chain_head where singleton_key"
  );
  const sequence = result.rows[0]?.last_sequence;
  assert(sequence);
  return sequence;
}

async function verifyReadPerformance(
  pool: Pool,
  fixture: CapacityFixture,
  principal: SurfacePrincipal
): Promise<{ readonly metrics: readonly Metric[]; readonly concurrentP95Ms: number }> {
  // Direct fixture: each measured read carries its own synthetic allocation owner, as
  // the native request boundary does; the measured path is otherwise unchanged.
  const repository = new DirectReadRepository(pool, {
    cursorKey: Buffer.alloc(32, 41),
    transaction: SERVER_TRANSACTION
  });
  const metrics: Metric[] = [];
  metrics.push(
    await measure(
      "warm_list_documents",
      25,
      TARGETS_MS.warmList,
      async (sample) => {
        const index = Math.abs(sample) % fixture.boardIds.length;
        const result = await repository.executeRead(
          principal,
          "list_documents",
          surfaceInput({ board_id: fixture.boardIds[index] as string, cursor: null, limit: 100 })
        );
        assertPage(result, 100);
      },
      fixture.boardIds.length
    )
  );
  metrics.push(
    await measure(
      "warm_get_document_hash",
      25,
      TARGETS_MS.warmGet,
      async (sample) => {
        const index = Math.abs(sample) % fixture.visibleDocumentIds.length;
        const documentId = fixture.visibleDocumentIds[index] as string;
        const versionId = fixture.visibleVersionIds[index] as string;
        const result = await repository.executeRead(
          principal,
          "get_document_hash",
          surfaceInput({ document_id: documentId, version_id: versionId })
        );
        assertDocumentHash(result, documentId, versionId);
      },
      fixture.visibleDocumentIds.length
    )
  );
  metrics.push(
    await measure(
      "entitled_search",
      25,
      TARGETS_MS.entitledSearch,
      async (sample) => {
        const index = Math.abs(sample) % fixture.boardIds.length;
        const result = await repository.executeRead(
          principal,
          "search_documents",
          surfaceInput({
            board_id: fixture.boardIds[index] as string,
            query: "needle",
            cursor: null,
            limit: 100
          })
        );
        assertPage(result);
      },
      fixture.boardIds.length
    )
  );
  metrics.push(
    await measure("one_call_briefing", 20, TARGETS_MS.briefing, async () => {
      const result = await repository.executeRead(
        principal,
        "list_pending_actions",
        surfaceInput({ cursor: null, limit: ENVELOPE.briefingItems })
      );
      assertBriefing(result);
    })
  );

  const headBefore = await readAuditHead(pool);
  const concurrent = Array.from({ length: ENVELOPE.concurrentMcpRequests }, (_, index) =>
    (async (): Promise<number> => {
      const started = performance.now();
      const boardIndex = index % fixture.boardIds.length;
      if (index < 40) {
        const documentId = fixture.visibleDocumentIds[boardIndex] as string;
        const versionId = fixture.visibleVersionIds[boardIndex] as string;
        const result = await repository.executeRead(
          principal,
          "get_document_hash",
          surfaceInput({ document_id: documentId, version_id: versionId })
        );
        assertDocumentHash(result, documentId, versionId);
      } else if (index < 60) {
        const result = await repository.executeRead(
          principal,
          "list_documents",
          surfaceInput({
            board_id: fixture.boardIds[boardIndex] as string,
            cursor: null,
            limit: 100
          })
        );
        assertPage(result, 100);
      } else if (index < 80) {
        const result = await repository.executeRead(
          principal,
          "search_documents",
          surfaceInput({
            board_id: fixture.boardIds[boardIndex] as string,
            query: "needle",
            cursor: null,
            limit: 100
          })
        );
        assertPage(result);
      } else if (index < 90) {
        const result = await repository.executeRead(
          principal,
          "search_documents",
          surfaceInput({
            board_id: fixture.boardIds[boardIndex] as string,
            query: "restrictedneedle",
            cursor: null,
            limit: 100
          })
        );
        assertEmptySearch(result);
      } else {
        const result = await repository.executeRead(
          principal,
          "list_pending_actions",
          surfaceInput({ cursor: null, limit: ENVELOPE.briefingItems })
        );
        assertBriefing(result);
      }
      return performance.now() - started;
    })()
  );
  const concurrentDurations = await Promise.all(concurrent);
  assert.equal(await readAuditHead(pool), headBefore, "read-only MCP load appended an audit event");
  return { metrics, concurrentP95Ms: roundMilliseconds(percentile95(concurrentDurations)) };
}

async function verifyAuditAppendPerformance(
  pool: Pool,
  actor: AuthorizedActorFixture,
  context: RequestDatabaseContext
): Promise<Metric> {
  return measure("audit_append", 20, TARGETS_MS.auditAppend, async (sample) => {
    const eventOffset = sample < 0 ? 100 + Math.abs(sample) : sample;
    const eventId = testId(9_000_100 + eventOffset);
    const appended = await withRequestTransaction(
      pool,
      context,
      (client) =>
        appendAuditEventsInTransaction(client, [
          {
            organizationId: actor.organizationId,
            event: {
              eventId,
              eventType: "context_read",
              actorMemberId: actor.memberId,
              actorClientId: actor.clientId,
              tokenJti: actor.tokenJti,
              entityType: "performance_probe",
              entityId: actor.boardId,
              boardId: actor.boardId,
              origin: "mcp",
              details: { sample },
              schemaVersion: 1
            }
          }
        ]),
      SERVER_TRANSACTION
    );
    assert.equal(appended.length, 1);
    assert.equal(appended[0]?.eventId, eventId);
  });
}

const CONSENT_CAPABILITIES = { elicitation: { form: {} } } as const;

function consentStageInput(sample: number, actor: AuthorizedActorFixture): StageActionInput {
  const normalized = Math.abs(sample);
  const base = 8_000_000 + normalized * 20;
  const confirmationCode = `PERF${String(normalized).padStart(4, "0")}`;
  return {
    stageId: testId(base),
    inputRequiredAttemptId: testId(base + 1),
    boardId: actor.boardId,
    actingForMemberId: null,
    actionCode: "update_board",
    targetType: "board",
    targetId: actor.boardId,
    canonicalSchema: "boardagent.board-update.v1",
    canonicalPayload: { boardId: actor.boardId, sample: normalized },
    packageSha256: null,
    nonce: Buffer.alloc(32, normalized % 256),
    confirmationCode,
    accessTokenRecordId: actor.accessTokenRecordId,
    exactOrigin: "https://client.example",
    originalName: "update_board",
    originalArguments: { board_id: actor.boardId, sample: normalized },
    clientCapabilities: CONSENT_CAPABILITIES,
    embeddedForm: { type: "object", required: ["approve", "confirmation_code"] },
    embeddedResult: { message: "Confirm benchmark action", confirmationCode },
    requestStateBytes: Buffer.alloc(48, (normalized + 1) % 256),
    preparedRequestId: Buffer.from(`performance-prepared-${String(normalized)}`),
    auditEventIds: {
      stageReplaced: testId(base + 2),
      stageCreated: testId(base + 3),
      elicitationSent: testId(base + 4)
    }
  };
}

async function lockBenchmarkBoard(client: PoolClient, boardId: string): Promise<void> {
  const locked = await client.query<{ actor_ready: boolean; state: string }>(
    "select actor_ready,state from boardagent_lock_board_root($1)",
    [boardId]
  );
  assert.deepEqual(locked.rows[0], { actor_ready: true, state: "active" });
}

async function oneConsentServerSample(
  pool: Pool,
  actor: AuthorizedActorFixture,
  context: RequestDatabaseContext,
  sample: number
): Promise<number> {
  const input = consentStageInput(sample, actor);
  const started = performance.now();
  const staged = await withRequestTransaction(
    pool,
    context,
    (client) =>
      stageActionInTransaction(client, input, (requestClient) =>
        lockBenchmarkBoard(requestClient, actor.boardId)
      ),
    SERVER_TRANSACTION
  );
  const normalized = Math.abs(sample);
  const base = 8_000_000 + normalized * 20;
  const confirmationCode = `PERF${String(normalized).padStart(4, "0")}`;
  const confirmed = await withRequestTransaction(
    pool,
    context,
    (client) =>
      confirmStagedActionInTransaction(
        client,
        {
          stageId: staged.stageId,
          consentRecordId: testId(base + 5),
          retryRequestId: Buffer.from(`performance-retry-${String(normalized)}`),
          originalArguments: input.originalArguments,
          clientCapabilities: input.clientCapabilities,
          exactOrigin: input.exactOrigin,
          requestStateBytes: input.requestStateBytes,
          responseAction: "accept",
          inputResponse: { approve: true, confirmation_code: confirmationCode },
          auditEventIds: {
            consentRecorded: testId(base + 6),
            consentRejected: testId(base + 7)
          }
        },
        async (requestClient) => {
          await lockBenchmarkBoard(requestClient, actor.boardId);
          return { payloadSha256: staged.payloadSha256, packageSha256: null };
        },
        async () => ({ value: null, auditEvents: [] })
      ),
    SERVER_TRANSACTION
  );
  assert.equal(confirmed.confirmed, true);
  return performance.now() - started;
}

async function verifyConsentPerformance(
  pool: Pool,
  actor: AuthorizedActorFixture,
  context: RequestDatabaseContext
): Promise<Metric> {
  const warmupDurations: number[] = [];
  for (const sample of [-1, -2, -3]) {
    warmupDurations.push(await oneConsentServerSample(pool, actor, context, sample));
  }
  assert.equal(warmupDurations.length, 3);
  const durations: number[] = [];
  for (let sample = 10; sample < 30; sample += 1) {
    durations.push(await oneConsentServerSample(pool, actor, context, sample));
  }
  const rawP95 = percentile95(durations);
  assert(
    rawP95 <= TARGETS_MS.consentServer,
    `consent server p95 ${roundMilliseconds(rawP95).toFixed(2)}ms exceeds ${String(TARGETS_MS.consentServer)}ms`
  );
  return {
    name: "consent_stage_plus_confirmation_server_time",
    samples: durations.length,
    p95Ms: roundMilliseconds(rawP95),
    maximumMs: roundMilliseconds(Math.max(...durations)),
    targetMs: TARGETS_MS.consentServer
  };
}

async function main(): Promise<void> {
  await withDisposableDatabase(async (pool) => {
    const fixture = await seedCapacityFixture(pool);
    const fixtureCounts = await readAndAssertFixtureCounts(pool);
    const { principal, context } = await createPrincipal(pool, fixture.actor);
    process.stdout.write("phase1-performance: measure real forced-RLS paths\n");
    const reads = await verifyReadPerformance(pool, fixture, principal);
    const audit = await verifyAuditAppendPerformance(pool, fixture.actor, context);
    const consent = await verifyConsentPerformance(pool, fixture.actor, context);
    const result = {
      schemaVersion: "boardagent.phase1-performance-result.v1",
      status: "passed",
      fixture: {
        kind: "disposable-statistical-envelope",
        counts: fixtureCounts,
        syntheticAuditHistoryIsEvidence: false
      },
      metrics: [...reads.metrics, audit, consent],
      concurrentMcp: {
        requests: ENVELOPE.concurrentMcpRequests,
        incorrectAuthorizationResultsOrEvents: 0,
        p95Ms: reads.concurrentP95Ms
      },
      boundary: {
        proves: "Phase-1 deterministic microbenchmarks at the frozen D2-054 row envelope",
        doesNotProve:
          "T9 deployment load profile, global audit-head critical-path share, restore RPO/RTO, or hardened-beta release readiness"
      }
    } as const;
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  });
}

const invokedPath = process.argv[1];
if (invokedPath && import.meta.url === pathToFileURL(path.resolve(invokedPath)).href) {
  await main();
}
