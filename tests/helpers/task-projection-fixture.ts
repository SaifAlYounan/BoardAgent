import { createHash } from "node:crypto";
import type { Pool } from "pg";
import { canonicalJson } from "../../lib/contracts/src/canonical.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import { appendAuditEventsInTransaction } from "../../lib/db/src/transactions/audit.js";
import { seedAuthorizedActor, testId, type AuthorizedActorFixture } from "./authorized-actor.js";

const hash = (bytes: Uint8Array | string) => createHash("sha256").update(bytes).digest();
const jsonBytes = (value: unknown) => Buffer.from(canonicalJson(value), "utf8");

// Normal constrained synthetic storage only. These rows let a SELECT test exercise a
// populated task graph (evidence, latest review, closure, correction cycle) and a fresh
// meeting recusal. They are not public task ceremonies, signed closures or accepted acts.
export async function seedTaskSyntheticConsent(
  pool: Pool,
  actor: AuthorizedActorFixture,
  target: {
    id: string;
    type: "task" | "meeting";
    actionCode: "review_task_evidence" | "close_task" | "correct_task" | "manage_recusal";
    idBase: number;
  }
) {
  const stage = testId(target.idBase),
    attempt = testId(target.idBase + 1);
  const consent = testId(target.idBase + 2),
    audit = testId(target.idBase + 3);
  const payload = jsonBytes({
    schemaVersion: "boardagent.synthetic-storage-consent.v1",
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
     values($1,$2,$3,$4,'${target.actionCode}',$5,$6,'boardagent.synthetic-storage-consent.v1',
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
     values($1,$2,$3,'2026-07-28','2026-07-28','boardagent.mrtr.v1','tools/call','${target.actionCode}',
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
      Buffer.from(`prepared-${String(target.idBase)}`),
      Buffer.from(`retry-${String(target.idBase)}`),
      unique("response")
    ]
  );
  await pool.query(
    `insert into consent_records(id,organization_id,board_id,stage_id,input_required_attempt_id,actor_member_id,
     action_code,target_type,target_id,canonical_schema,payload_sha256,protected_code_record_sha256,
     access_token_record_id,token_jti,client_id,exact_origin,staged_at,record_sha256)
     values($1,$2,$3,$4,$5,$6,'${target.actionCode}',$7,$8,'boardagent.consent-record.v1',$9,$10,
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
  if (target.actionCode === "manage_recusal")
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

export const TASK_FIXTURE_REQUIRED_EVIDENCE = {
  text: 'Canonical report Δ 🙂\n"quoted"\\',
  items: [{ kind: "document", minimum: 1 }, [], null, true],
  wide: 1e40,
  tiny: 1e-40
};

export async function seedTaskProjectionFixture(pool: Pool) {
  const actor = await seedAuthorizedActor(pool, {
    seatRole: "voting_member",
    isSecretary: true,
    scopes: ["governance:read", "secretariat:admin"]
  });
  const meetingId = testId(240_000),
    minutesId = testId(240_001),
    versionId = testId(240_002);
  const taskId = testId(240_010),
    replacementId = testId(240_011);
  const evidenceIds = [testId(240_020), testId(240_021)] as const;
  const reviewId = testId(240_030),
    closureId = testId(240_040),
    cycleId = testId(240_050);
  // The minutes lineage guard checks the meeting/minutes tips at commit, so the source
  // rows are seeded in one transaction (the same shape the task transaction tests use).
  const seed = await pool.connect();
  try {
    await seed.query("begin");
    await seed.query(
      `insert into meetings(id,organization_id,board_id,title,state,scheduled_start,scheduled_end,created_by)
       values ($1,$2,$3,'Synthetic task projection meeting','called',
         transaction_timestamp()+interval '1 hour',transaction_timestamp()+interval '2 hours',$4)`,
      [meetingId, actor.organizationId, actor.boardId, actor.memberId]
    );
    await seed.query(
      "insert into minutes(id,organization_id,board_id,meeting_id,created_by) values ($1,$2,$3,$4,$5)",
      [minutesId, actor.organizationId, actor.boardId, meetingId, actor.memberId]
    );
    await seed.query(
      `insert into minutes_versions(id,organization_id,board_id,minutes_id,version,canonical_schema,
         canonical_text,canonical_sha256,package_base_sha256,created_by)
       values ($1,$2,$3,$4,1,'boardagent.minutes.v1','Synthetic task projection source.',$5,$5,$6)`,
      [versionId, actor.organizationId, actor.boardId, minutesId, hash("minutes"), actor.memberId]
    );
    await seed.query(
      "update minutes set current_version_id=$1,row_version=row_version+1 where id=$2",
      [versionId, minutesId]
    );
    await seed.query(
      "update meetings set current_minutes_id=$1,row_version=row_version+1 where id=$2",
      [minutesId, meetingId]
    );
    await seed.query("commit");
  } catch (error) {
    await seed.query("rollback");
    throw error;
  } finally {
    seed.release();
  }
  // The closed action item carries a minutes source, two evidence rows (one reviewed),
  // a closure and a correction cycle to an open replacement task without a source.
  await pool.query(
    `insert into tasks(id,organization_id,board_id,owner_member_id,due_at,description_schema,
       canonical_description,required_evidence,task_sha256,state,created_by,source_meeting_id,
       source_minutes_id,source_minutes_version_id,source_minutes_sha256,source_locator,completed_at)
     values ($1,$2,$3,$4,transaction_timestamp()+interval '1 day','boardagent.task.v1',
       'Deliver the synthetic report Δ 🙂.',$5::jsonb,$6,'completed',$4,$7,$8,$9,$10,
       '{"section":"Actions","item":2}'::jsonb,transaction_timestamp()-interval '1 minute')`,
    [
      taskId,
      actor.organizationId,
      actor.boardId,
      actor.memberId,
      JSON.stringify(TASK_FIXTURE_REQUIRED_EVIDENCE),
      hash("task"),
      meetingId,
      minutesId,
      versionId,
      hash("minutes")
    ]
  );
  await pool.query(
    `insert into tasks(id,organization_id,board_id,owner_member_id,due_at,description_schema,
       canonical_description,required_evidence,task_sha256,state,created_by)
     values ($1,$2,$3,$4,transaction_timestamp()+interval '2 days','boardagent.task.v1',
       'Replacement synthetic report.','{"text":"Replacement."}'::jsonb,$5,'open',$4)`,
    [replacementId, actor.organizationId, actor.boardId, actor.memberId, hash("replacement")]
  );
  await pool.query(
    `insert into task_evidence(id,organization_id,board_id,task_id,owner_member_id,canonical_text,
       document_references,resource_references,canonical_sha256,state,submitted_at)
     values ($1,$2,$3,$4,$5,'First synthetic evidence "Δ".',
       '[{"document_id":"01993400-0000-7000-8000-000000000101","version":1}]'::jsonb,'[]'::jsonb,
       $6,'submitted',transaction_timestamp()-interval '3 minutes')`,
    [
      evidenceIds[0],
      actor.organizationId,
      actor.boardId,
      taskId,
      actor.memberId,
      hash("evidence-1")
    ]
  );
  await pool.query(
    `insert into task_evidence(id,organization_id,board_id,task_id,owner_member_id,canonical_text,
       document_references,resource_references,canonical_sha256,state,submitted_at)
     values ($1,$2,$3,$4,$5,null,'[]'::jsonb,
       '[{"uri":"board://synthetic/documents/1","note":"🙂"},[1e40,null]]'::jsonb,
       $6,'accepted',transaction_timestamp()-interval '2 minutes')`,
    [
      evidenceIds[1],
      actor.organizationId,
      actor.boardId,
      taskId,
      actor.memberId,
      hash("evidence-2")
    ]
  );
  const review = await seedTaskSyntheticConsent(pool, actor, {
    id: taskId,
    type: "task",
    actionCode: "review_task_evidence",
    idBase: 240_100
  });
  await pool.query(
    `insert into task_evidence_reviews(id,organization_id,evidence_id,secretary_member_id,decision,reason,consent_record_id)
     values ($1,$2,$3,$4,'accepted','Synthetic acceptance Δ.',$5)`,
    [reviewId, actor.organizationId, evidenceIds[1], actor.memberId, review.consent]
  );
  const closure = await seedTaskSyntheticConsent(pool, actor, {
    id: taskId,
    type: "task",
    actionCode: "close_task",
    idBase: 240_110
  });
  await pool.query(
    `insert into task_closures(id,organization_id,board_id,task_id,primary_evidence_id,
       accepted_evidence_manifest,source_minutes_sha256,secretary_member_id,consent_record_id,closure_sha256)
     values ($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,$10)`,
    [
      closureId,
      actor.organizationId,
      actor.boardId,
      taskId,
      evidenceIds[1],
      JSON.stringify([{ evidence_id: evidenceIds[1], sha256: hash("evidence-2").toString("hex") }]),
      hash("minutes"),
      actor.memberId,
      closure.consent,
      hash("closure")
    ]
  );
  const cycle = await seedTaskSyntheticConsent(pool, actor, {
    id: taskId,
    type: "task",
    actionCode: "correct_task",
    idBase: 240_120
  });
  await pool.query(
    `insert into task_correction_cycles(id,organization_id,board_id,prior_task_id,prior_closure_id,
       replacement_task_id,secretary_member_id,reason,consent_record_id)
     values ($1,$2,$3,$4,$5,$6,$7,'Synthetic correction Δ.',$8)`,
    [
      cycleId,
      actor.organizationId,
      actor.boardId,
      taskId,
      closureId,
      replacementId,
      actor.memberId,
      cycle.consent
    ]
  );
  return {
    actor,
    meetingId,
    minutesId,
    taskId,
    replacementId,
    evidenceIds,
    reviewId,
    closureId,
    cycleId,
    // A meeting exclusion recuses the member from every task rooted in that meeting.
    exclude: async () => {
      const recusal = await seedTaskSyntheticConsent(pool, actor, {
        id: meetingId,
        type: "meeting",
        actionCode: "manage_recusal",
        idBase: 240_130
      });
      const inserted = await pool.query(
        `insert into meeting_exclusions(id,organization_id,board_id,meeting_id,member_id,version,
           state,reason,actor_member_id,consent_record_id,audit_event_id)
         values($1,$2,$3,$4,$5,1,'excluded','Synthetic task projection recusal',$5,$6,$7) returning id`,
        [
          testId(240_140),
          actor.organizationId,
          actor.boardId,
          meetingId,
          actor.memberId,
          recusal.consent,
          recusal.audit
        ]
      );
      if (inserted.rowCount !== 1) throw new Error("task fixture recusal was not stored");
    }
  };
}
