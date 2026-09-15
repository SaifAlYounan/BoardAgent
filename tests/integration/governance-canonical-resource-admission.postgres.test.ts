import { createHash } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { expect, it } from "vitest";
import { loadAdmittedGovernanceCanonicalResource } from "../../artifacts/server/src/governance-canonical-resource.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import { canonicalJson } from "../../lib/contracts/src/canonical.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import { appendAuditEventsInTransaction } from "../../lib/db/src/transactions/audit.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import {
  seedAuthorizedActor,
  testId,
  type AuthorizedActorFixture
} from "../helpers/authorized-actor.js";

const hash = (bytes: Uint8Array | string) => createHash("sha256").update(bytes).digest();
const jsonBytes = (value: unknown) => Buffer.from(canonicalJson(value), "utf8");

// Normal constrained synthetic records only. This fixture exercises storage and
// actual RLS, not a public recusal/confirmation ceremony or accepted governance act.
async function recusalEvidence(
  pool: Pool,
  actor: AuthorizedActorFixture,
  target: {
    id: string;
    type: "minutes" | "vote";
    idBase: number;
  }
) {
  const stage = testId(target.idBase),
    attempt = testId(target.idBase + 1);
  const consent = testId(target.idBase + 2),
    audit = testId(target.idBase + 3);
  const payload = jsonBytes({
    schemaVersion: "boardagent.synthetic-recusal.v1",
    targetType: target.type,
    targetId: target.id,
    memberId: actor.memberId
  });
  const digest = hash(payload);
  const unique = (label: string) => hash(`${String(target.idBase)}:${label}`);
  await pool.query(
    `insert into action_stages(id,organization_id,board_id,actor_member_id,action_code,target_type,target_id,
     canonical_schema,canonicalization_version,canonical_payload,payload_sha256,nonce_sha256,
     protected_code_sha256,client_id,access_token_record_id,token_jti,exact_origin,context_sha256,state,expires_at)
     values($1,$2,$3,$4,'manage_recusal',$5,$6,'boardagent.synthetic-recusal.v1',
     'RFC8785+NFC-LF-v1',$7,$8,$9,$10,$11,$12,$13,'https://client.example',$14,'active',transaction_timestamp()+interval '10 minutes')`,
    [
      stage,
      actor.organizationId,
      actor.boardId,
      actor.memberId,
      target.type,
      target.id,
      payload,
      digest,
      unique("nonce"),
      unique("code"),
      actor.clientId,
      actor.accessTokenRecordId,
      actor.tokenJti,
      unique("context")
    ]
  );
  await pool.query(
    "update action_stages set state='confirmed',confirmed_at=transaction_timestamp() where id=$1",
    [stage]
  );
  const requestState = Buffer.from(unique("request-state"));
  await pool.query(
    `insert into input_required_attempts(id,organization_id,stage_id,protocol_version,protocol_header_version,
     result_meta_version,original_method,original_name,original_arguments_sha256,capabilities_sha256,
     embedded_form_sha256,embedded_result_sha256,request_state_bytes,request_state_sha256,
     prepared_request_id,retry_request_id,input_response_sha256,response_action,state,completed_at)
     values($1,$2,$3,'2026-07-28','2026-07-28','boardagent.mrtr.v1','tools/call','manage_recusal',
     $4,$5,$6,$7,$8,$9,$10,$11,$12,'accept','confirmed',transaction_timestamp())`,
    [
      attempt,
      actor.organizationId,
      stage,
      digest,
      unique("capabilities"),
      unique("form"),
      unique("result"),
      requestState,
      hash(requestState),
      Buffer.from(`prepared-${target.idBase}`),
      Buffer.from(`retry-${target.idBase}`),
      unique("response")
    ]
  );
  await pool.query(
    `insert into consent_records(id,organization_id,board_id,stage_id,input_required_attempt_id,actor_member_id,
     action_code,target_type,target_id,canonical_schema,payload_sha256,protected_code_record_sha256,
     access_token_record_id,token_jti,client_id,exact_origin,staged_at,record_sha256)
     values($1,$2,$3,$4,$5,$6,'manage_recusal',$7,$8,'boardagent.consent-record.v1',$9,$10,
     $11,$12,$13,'https://client.example',transaction_timestamp(),$14)`,
    [
      consent,
      actor.organizationId,
      actor.boardId,
      stage,
      attempt,
      actor.memberId,
      target.type,
      target.id,
      digest,
      unique("protected-code-record"),
      actor.accessTokenRecordId,
      actor.tokenJti,
      actor.clientId,
      unique("consent-record")
    ]
  );
  await withRequestTransaction(
    pool,
    actor.context,
    (client) =>
      appendAuditEventsInTransaction(client, [
        {
          organizationId: actor.organizationId,
          consentRecordId: consent,
          event: {
            eventId: audit,
            eventType: "recusal_changed",
            actorMemberId: actor.memberId,
            actorClientId: actor.clientId,
            tokenJti: actor.tokenJti,
            entityType: target.type,
            entityId: target.id,
            boardId: actor.boardId,
            origin: "mcp",
            details: { syntheticStorageFixture: true, memberId: actor.memberId },
            schemaVersion: 1
          }
        }
      ]),
    { assumeRole: "boardagent_server" }
  );
  return { consent, audit };
}

it("loads exact admitted minutes, review and decision-package resources under the actual server role", async () => {
  await withMigratedDatabase("governance_canonical", async (pool) => {
    const actor = await seedAuthorizedActor(pool, {
      seatRole: "voting_member",
      isSecretary: true,
      scopes: ["governance:read", "minutes:act", "secretariat:admin"]
    });
    // Separate parent minutes let both byte/text aliases test a fresh committed
    // exclusion after their own preflight, without modifying immutable exclusions.
    const roots = [
      {
        meeting: testId(200000),
        id: testId(200001),
        version: testId(200002),
        text: "# Minutes Δ 🙂\nExact first body.\n"
      },
      {
        meeting: testId(200010),
        id: testId(200011),
        version: testId(200012),
        text: "# Review minutes Δ 🙂\nExact second body.\n"
      }
    ];
    const seed = await pool.connect();
    try {
      await seed.query("begin");
      for (const root of roots) {
        await seed.query(
          `insert into meetings(id,organization_id,board_id,title,scheduled_start,scheduled_end,created_by)
        values($1,$2,$3,'Synthetic resource meeting',transaction_timestamp()+interval '1 hour',transaction_timestamp()+interval '2 hours',$4)`,
          [root.meeting, actor.organizationId, actor.boardId, actor.memberId]
        );
        await seed.query(
          `insert into minutes(id,organization_id,board_id,meeting_id,created_by) values($1,$2,$3,$4,$5)`,
          [root.id, actor.organizationId, actor.boardId, root.meeting, actor.memberId]
        );
        await seed.query(
          `insert into minutes_versions(id,organization_id,board_id,minutes_id,version,canonical_schema,
        canonical_text,canonical_sha256,package_base_sha256,created_by)
        values($1,$2,$3,$4,1,'boardagent.minutes.v1',$5,$6,$7,$8)`,
          [
            root.version,
            actor.organizationId,
            actor.boardId,
            root.id,
            root.text,
            hash(root.text),
            hash(
              jsonBytes({ minutesId: root.id, version: 1, sha256: hash(root.text).toString("hex") })
            ),
            actor.memberId
          ]
        );
        await seed.query(
          "update minutes set current_version_id=$2,state='published_review',row_version=row_version+1 where id=$1",
          [root.id, root.version]
        );
        await seed.query(
          "update meetings set current_minutes_id=$2,row_version=row_version+1 where id=$1",
          [root.meeting, root.id]
        );
      }
      await seed.query("commit");
    } catch (error) {
      await seed.query("rollback");
      throw error;
    } finally {
      seed.release();
    }
    const minutes = roots[0]!,
      reviewed = roots[1]!;
    const reviewId = testId(200020),
      idempotencyId = testId(200021);
    const reviewBytes = jsonBytes({
      schemaVersion: "boardagent.minutes-comment.v1",
      minutesId: reviewed.id,
      baseVersion: 1,
      baseSha256: hash(reviewed.text).toString("hex"),
      comment: "Retain exact Mining wording Δ 🙂.\n",
      citations: []
    });
    await pool.query(
      `insert into idempotency_records(id,organization_id,actor_member_id,client_id,operation,
      idempotency_key,request_sha256,state,expires_at) values($1,$2,$3,$4,'comment_minutes',
      'governance-canonical-review-fixture',$5,'in_progress',transaction_timestamp()+interval '1 day')`,
      [idempotencyId, actor.organizationId, actor.memberId, actor.clientId, hash(reviewBytes)]
    );
    await pool.query(
      `insert into minutes_review_items(id,organization_id,board_id,minutes_id,item_kind,schema_version,
      author_member_id,author_seat_role,base_version_id,base_sha256,exact_anchor,canonical_payload,payload_sha256,idempotency_record_id)
      values($1,$2,$3,$4,'comment','boardagent.minutes-comment.v1',$5,'voting_member',$6,$7,
      '{"kind":"whole_package"}',$8,$9,$10)`,
      [
        reviewId,
        actor.organizationId,
        actor.boardId,
        reviewed.id,
        actor.memberId,
        reviewed.version,
        hash(reviewed.text),
        reviewBytes,
        hash(reviewBytes),
        idempotencyId
      ]
    );

    const approval = testId(200100),
      profile = testId(200101),
      ruleset = testId(200102),
      matter = testId(200103),
      rule = testId(200104),
      evaluation = testId(200105),
      vote = testId(200106),
      resolution = testId(200107),
      decision = testId(200108);
    const emptyObject = jsonBytes({}),
      emptyArray = jsonBytes([]),
      resolutionText = "RESOLVED: retain exact synthetic Mining record.\n";
    const packageBytes = jsonBytes({
      schemaVersion: "boardagent.decision-package.v1",
      fixture: "canonical resource SQL only Δ 🙂",
      voteId: vote,
      packageVersion: 1,
      resolutionVersionId: resolution,
      resolutionSha256: hash(resolutionText).toString("hex")
    });
    // The package is a constrained raw canonical storage fixture. The public
    // decision-package schema/creation ceremony is not exercised by this test.
    await pool.query(
      `insert into approval_rules(id,organization_id,board_id,schema_version,threshold_numerator,
      threshold_denominator,quorum_numerator,quorum_denominator,approval_denominator,abstentions_count_for_quorum,
      tie_behavior,proxy_policy,close_mode,canonical_sha256,created_by)
      values($1,$2,$3,'boardagent.approval-rule.v1',1,2,1,2,'eligible',true,'reject','principal_supersedes_proxy',
      'secretariat_confirmed',$4,$5)`,
      [approval, actor.organizationId, actor.boardId, hash("synthetic approval"), actor.memberId]
    );
    await pool.query(
      `insert into governance_profiles(id,organization_id,board_id,version,state,schema_version,
      canonical_payload,canonical_sha256,source_agreement_references,created_by)
      values($1,$2,$3,1,'draft','boardagent.governance-profile.v1','{}',$4,'[]',$5)`,
      [profile, actor.organizationId, actor.boardId, hash(emptyObject), actor.memberId]
    );
    await pool.query(
      `insert into rulesets(id,organization_id,board_id,profile_id,version,state,schema_version,
      canonical_payload,canonical_sha256,created_by) values($1,$2,$3,$4,1,'draft','boardagent.ruleset.v1','{}',$5,$6)`,
      [ruleset, actor.organizationId, actor.boardId, profile, hash(emptyObject), actor.memberId]
    );
    await pool.query(
      `insert into matter_types(id,ruleset_id,code,name,strict_fact_schema,schema_sha256)
      values($1,$2,'synthetic_read','Synthetic resource read','{}',$3)`,
      [matter, ruleset, hash(emptyObject)]
    );
    await pool.query(
      `insert into ruleset_rules(id,ruleset_id,matter_type_id,priority,specificity,condition_tree,
      approval_rule_id,canonical_sha256) values($1,$2,$3,1,1,'{}',$4,$5)`,
      [rule, ruleset, matter, approval, hash("synthetic selected rule")]
    );
    await pool.query(
      `insert into matter_evaluations(id,organization_id,board_id,requester_member_id,profile_id,ruleset_id,
      matter_type_id,engine_version,canonical_facts,facts_sha256,result,matched_rule_id,candidate_rule_ids,citation_snapshot,result_sha256)
      values($1,$2,$3,$4,$5,$6,$7,'boardagent.rules-engine.v1','{}',$8,'matched',$9,array[$9::uuid],'[]',$10)`,
      [
        evaluation,
        actor.organizationId,
        actor.boardId,
        actor.memberId,
        profile,
        ruleset,
        matter,
        hash(emptyObject),
        rule,
        hash("synthetic evaluation")
      ]
    );
    await pool.query(
      `insert into votes(id,organization_id,board_id,title,approval_rule_id,governance_profile_id,ruleset_id,
      close_mode,created_by) values($1,$2,$3,'Synthetic decision resource',$4,$5,$6,'secretariat_confirmed',$7)`,
      [vote, actor.organizationId, actor.boardId, approval, profile, ruleset, actor.memberId]
    );
    await pool.query(
      `insert into resolution_versions(id,organization_id,board_id,vote_id,version,canonical_schema,
      canonical_text,canonical_sha256,author_member_id) values($1,$2,$3,$4,1,'boardagent.resolution.v1',$5,$6,$7)`,
      [
        resolution,
        actor.organizationId,
        actor.boardId,
        vote,
        resolutionText,
        hash(resolutionText),
        actor.memberId
      ]
    );
    await pool.query(
      `insert into decision_packages(id,organization_id,board_id,vote_id,version,schema_version,resolution_version_id,
      resolution_sha256,submission_manifest,submission_manifest_sha256,document_manifest,document_manifest_sha256,
      question_cutoff_manifest,question_cutoff_sha256,approval_rule_id,approval_rule_sha256,governance_profile_id,
      governance_profile_sha256,ruleset_id,ruleset_sha256,electorate_sha256,canonical_payload,package_sha256,created_by,
      matter_evaluation_id,matter_evaluation_result_sha256,selected_ruleset_rule_id,selected_ruleset_rule_sha256)
      values($1,$2,$3,$4,1,'boardagent.decision-package.v1',$5,$6,'[]',$7,'[]',$7,'[]',$7,$8,$9,$10,$11,$12,$11,
      $7,$13,$14,$15,$16,$17,$18,$19)`,
      [
        decision,
        actor.organizationId,
        actor.boardId,
        vote,
        resolution,
        hash(resolutionText),
        hash(emptyArray),
        approval,
        hash("synthetic approval"),
        profile,
        hash(emptyObject),
        ruleset,
        packageBytes,
        hash(packageBytes),
        actor.memberId,
        evaluation,
        hash("synthetic evaluation"),
        rule,
        hash("synthetic selected rule")
      ]
    );
    await pool.query(
      "update votes set current_resolution_version_id=$2,current_decision_package_id=$3,row_version=row_version+1 where id=$1",
      [vote, resolution, decision]
    );

    const lanes = [
      {
        kind: "minutes",
        parentId: minutes.id,
        id: minutes.version,
        bytes: Buffer.from(minutes.text),
        oracle: `select version_row.canonical_text from minutes join minutes_versions as version_row on version_row.minutes_id=minutes.id
        where minutes.board_id=$1 and minutes.id=$2 and version_row.version=$3`
      },
      {
        kind: "minutes_review",
        parentId: reviewed.id,
        id: reviewId,
        bytes: reviewBytes,
        oracle: `select item.canonical_payload from minutes join minutes_review_items as item on item.minutes_id=minutes.id
        where minutes.board_id=$1 and minutes.id=$2 and item.id=$3`
      },
      {
        kind: "decision_package",
        parentId: vote,
        id: decision,
        bytes: packageBytes,
        oracle: `select package.canonical_payload from votes as vote join decision_packages as package on package.vote_id=vote.id
        where vote.board_id=$1 and vote.id=$2 and package.version=$3 and not boardagent_member_vote_recused(vote.id,
        boardagent_context_uuid('boardagent.member_id'))`
      }
    ] as const;
    const rawByKind = new Map<string, Buffer>();
    // Real original queries run before saturation. No oracle content query is
    // hidden inside the later refusal-before-content measurement.
    await withRequestTransaction(
      pool,
      actor.context,
      async (client) => {
        expect((await client.query("select current_user")).rows[0].current_user).toBe(
          "boardagent_server"
        );
        for (const lane of lanes) {
          const original = await client.query(lane.oracle, [
            actor.boardId,
            lane.parentId,
            lane.kind === "minutes_review" ? reviewId : 1
          ]);
          expect(original.rows).toHaveLength(1);
          const bytes =
            lane.kind === "minutes"
              ? Buffer.from(original.rows[0].canonical_text, "utf8")
              : (original.rows[0].canonical_payload as Buffer);
          expect(bytes).toEqual(lane.bytes);
          rawByKind.set(lane.kind, bytes);
        }
        const lengths = await client.query(
          "select length(canonical_text) as characters,octet_length(convert_to(canonical_text,'UTF8')) as bytes from minutes_versions where id=$1",
          [minutes.version]
        );
        expect(lengths.rows[0].bytes).toBe(Buffer.byteLength(minutes.text));
        expect(lengths.rows[0].bytes).toBeGreaterThan(lengths.rows[0].characters);
      },
      { assumeRole: "boardagent_server" }
    );
    const manager = new ResponseAllocationManager();
    type Lane = (typeof lanes)[number];
    async function read(
      lane: Lane,
      options: {
        wrongBoard?: boolean;
        wrongParent?: boolean;
        wrongSelector?: boolean;
        wrongBound?: "id" | "length" | "digest";
        saturated?: boolean;
        afterMetadata?: () => Promise<void>;
      } = {}
    ) {
      const owner = manager.openRequest(new AbortController().signal);
      let metadata = 0,
        content = 0;
      try {
        const value = await owner.produce(() =>
          withRequestTransaction(
            pool,
            actor.context,
            async (client) => {
              expect((await client.query("select current_user")).rows[0].current_user).toBe(
                "boardagent_server"
              );
              const observed = {
                query: async (sql: string, values?: unknown[]) => {
                  const isMetadata = sql.includes("as byte_length");
                  if (!isMetadata) {
                    content += 1;
                    expect(manager.accounting.usedUnits).toBeGreaterThan(0);
                  }
                  const sent = values ? [...values] : undefined;
                  if (!isMetadata && sent && options.wrongBound) {
                    if (options.wrongBound === "id") sent[3] = testId(299999);
                    if (options.wrongBound === "length") sent[4] = lane.bytes.length + 1;
                    if (options.wrongBound === "digest") sent[5] = Buffer.alloc(32, 255);
                  }
                  const result = await client.query(sql, sent);
                  if (isMetadata) {
                    metadata += 1;
                    for (const row of result.rows) {
                      expect(Object.keys(row).sort()).toEqual([
                        "byte_length",
                        "id",
                        "sha256",
                        "version"
                      ]);
                      const raw = rawByKind.get(lane.kind)!;
                      expect(row).toEqual({
                        id: lane.id,
                        version: 1,
                        byte_length: raw.length,
                        sha256: hash(raw).toString("hex")
                      });
                    }
                    if (options.afterMetadata) {
                      expect(result.rows).toHaveLength(1);
                      await options.afterMetadata();
                    }
                  }
                  return result;
                }
              } as unknown as PoolClient;
              const common = {
                boardId: options.wrongBoard ? testId(299998) : actor.boardId,
                parentId: options.wrongParent ? testId(299997) : lane.parentId
              };
              return lane.kind === "minutes_review"
                ? loadAdmittedGovernanceCanonicalResource(observed, {
                    ...common,
                    kind: lane.kind,
                    itemId: options.wrongSelector ? testId(299996) : reviewId
                  })
                : loadAdmittedGovernanceCanonicalResource(observed, {
                    ...common,
                    kind: lane.kind,
                    version: options.wrongSelector ? 2 : 1
                  });
            },
            { assumeRole: "boardagent_server" }
          )
        );
        if (value) expect(value).toEqual({ id: lane.id, version: 1, bytes: lane.bytes });
        expect(metadata).toBe(1);
        expect(content).toBe(value || options.wrongBound || options.afterMetadata ? 1 : 0);
        if (content) {
          expect(manager.accounting.usedUnits).toBe(1);
          owner.nativeTerminal();
          expect(manager.accounting.usedUnits).toBe(1);
        }
        return value;
      } finally {
        if (options.saturated) {
          expect(metadata).toBe(1);
          expect(content).toBe(0);
        }
        owner.nativeTerminal();
        owner.collectorSettled();
      }
    }
    for (const lane of lanes) {
      expect(await read(lane)).not.toBeNull();
      expect(await read(lane, { wrongBoard: true })).toBeNull();
      expect(await read(lane, { wrongParent: true })).toBeNull();
      expect(await read(lane, { wrongSelector: true })).toBeNull();
      for (const wrongBound of ["id", "length", "digest"] as const)
        expect(await read(lane, { wrongBound })).toBeNull();
      expect(manager.accounting.usedUnits).toBe(0);
    }
    const small = responseAllocationPlan({
      kind: "canonical_resource",
      representation: "resource",
      sourceId: testId(290000),
      sourceVersion: "occupied",
      sha256: hash("{}").toString("hex"),
      canonicalBytes: 2
    });
    const occupied = Array.from({ length: 2048 }, () => manager.tryReserve(small));
    try {
      expect(manager.accounting.usedUnits).toBe(2048);
      for (const lane of lanes)
        await expect(read(lane, { saturated: true })).rejects.toBeInstanceOf(
          ResponseAllocationUnavailable
        );
    } finally {
      for (const lease of occupied) lease.release();
    }
    expect(manager.accounting.usedUnits).toBe(0);

    // Committed actual exclusion after each alias's real metadata statement.
    // Each uses a separate root; no immutable exclusion row is edited or lifted.
    for (const [index, lane] of lanes.entries()) {
      const type = lane.kind === "decision_package" ? "vote" : "minutes";
      const idBase = 201000 + index * 100;
      const evidence = await recusalEvidence(pool, actor, { type, id: lane.parentId, idBase });
      const value = await read(lane, {
        afterMetadata: async () => {
          if (type === "minutes") {
            const inserted = await pool.query(
              `insert into minutes_exclusions(id,organization_id,board_id,minutes_id,member_id,version,
            state,reason,actor_member_id,consent_record_id,audit_event_id)
            values($1,$2,$3,$4,$5,1,'excluded','Synthetic storage recusal fixture',$5,$6,$7) returning id`,
              [
                testId(idBase + 4),
                actor.organizationId,
                actor.boardId,
                lane.parentId,
                actor.memberId,
                evidence.consent,
                evidence.audit
              ]
            );
            expect(inserted.rowCount).toBe(1);
          } else {
            const inserted = await pool.query(
              `insert into vote_exclusions(id,organization_id,board_id,vote_id,member_id,version,
            state,reason,actor_member_id,consent_record_id)
            values($1,$2,$3,$4,$5,1,'excluded','Synthetic storage recusal fixture',$5,$6) returning id`,
              [
                testId(idBase + 4),
                actor.organizationId,
                actor.boardId,
                lane.parentId,
                actor.memberId,
                evidence.consent
              ]
            );
            expect(inserted.rowCount).toBe(1);
          }
        }
      });
      expect(value).toBeNull();
      expect(manager.accounting.usedUnits).toBe(0);
      expect(await read(lane)).toBeNull();
    }
    const fetchAudits = await pool.query(
      "select count(*)::integer as count from audit_events where event_type='resource_fetch'"
    );
    expect(fetchAudits.rows[0].count).toBe(0);
  });
}, 120_000);
