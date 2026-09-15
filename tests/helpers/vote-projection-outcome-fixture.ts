import { createHash, generateKeyPairSync } from "node:crypto";
import type { Pool } from "pg";
import { canonicalJson, type JsonValue } from "../../lib/contracts/src/canonical.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import { appendAuditEventsInTransaction } from "../../lib/db/src/transactions/audit.js";
import { testId, type AuthorizedActorFixture } from "./authorized-actor.js";

const hash = (bytes: Uint8Array | string) => createHash("sha256").update(bytes).digest();
const jsonBytes = (value: unknown) => Buffer.from(canonicalJson(value), "utf8");

// Normal constrained synthetic storage only. These rows let a SELECT test
// exercise a real nonempty package link and a fresh recusal. They are not public
// governance creation, signing, confirmation or accepted corporate acts.
async function syntheticCloseEvidence(
  pool: Pool,
  actor: AuthorizedActorFixture,
  target: {
    id: string;
    type: "vote";
    actionCode: "close_vote";
    packageSha256: Buffer | null;
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
     protected_code_sha256,client_id,access_token_record_id,token_jti,exact_origin,context_sha256,state,expires_at,package_sha256)
     values($1,$2,$3,$4,'${target.actionCode}',$5,$6,'boardagent.synthetic-storage-consent.v1',
     'RFC8785+NFC-LF-v1',$7,$8,$9,$10,$11,$12,$13,'https://client.example',$14,'active',transaction_timestamp()+interval '10 minutes',$15)`,
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
      unique("context"),
      target.packageSha256
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
      Buffer.from(`prepared-${target.idBase}`),
      Buffer.from(`retry-${target.idBase}`),
      unique("response")
    ]
  );
  await pool.query(
    `insert into consent_records(id,organization_id,board_id,stage_id,input_required_attempt_id,actor_member_id,
     action_code,target_type,target_id,canonical_schema,payload_sha256,protected_code_record_sha256,
     access_token_record_id,token_jti,client_id,exact_origin,staged_at,record_sha256,package_sha256)
     values($1,$2,$3,$4,$5,$6,'${target.actionCode}',$7,$8,'boardagent.consent-record.v1',$9,$10,
     $11,$12,$13,'https://client.example',transaction_timestamp(),$14,$15)`,
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
      unique("consent-record"),
      target.packageSha256
    ]
  );
  if (target.actionCode === "close_vote")
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
              eventType: "vote_closing",
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
  return { consent, audit, digest };
}

// This test-only helper starts with an existing draft vote/package and satisfied
// linked-question preconditions. It inserts ordinary constrained storage rows;
// it does not execute a close worker, persisted recomputation or public ceremony.
// The default synthetic certificate draft is intentionally not a valid issued certificate.
// The optional supplied draft is test-only and still passes every normal storage guard.
export interface SuppliedVoteProjectionCertificateDraft {
  readonly canonicalPayload: Buffer;
  readonly publicId: Buffer;
  readonly kid: string;
  readonly publicJwk: JsonValue;
}

export async function seedVoteProjectionOutcome(
  pool: Pool,
  actor: AuthorizedActorFixture,
  voteId: string,
  tallyJson: string,
  suppliedDraft?: SuppliedVoteProjectionCertificateDraft
) {
  const outcomeId = testId(224000),
    certificateId = testId(224001),
    keyId = testId(224002),
    clockId = testId(224003);
  const selected = await pool.query<{ package_id: string; package_sha256: Buffer }>(
    `select package.id as package_id,package.package_sha256
       from votes as vote join decision_packages as package on package.id=vote.current_decision_package_id
      where vote.id=$1 and vote.board_id=$2 and vote.organization_id=$3 and vote.state='draft'`,
    [voteId, actor.boardId, actor.organizationId]
  );
  if (selected.rows.length !== 1)
    throw new Error("outcome fixture requires one exact draft vote package");
  const bound = selected.rows[0]!;
  const evidence = await syntheticCloseEvidence(pool, actor, {
    id: voteId,
    type: "vote",
    actionCode: "close_vote",
    packageSha256: bound.package_sha256,
    idBase: 224100
  });
  const publicJwk =
    suppliedDraft === undefined
      ? generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" })
      : suppliedDraft.publicJwk;
  const keyKid = suppliedDraft?.kid ?? "vote-projection-fixture";
  await pool.query(
    `insert into crypto_key_registry(id,organization_id,kid,purpose,algorithm,
    public_jwk,nonsecret_locator,activated_at) values($1,$2,$4,'evidence_signing',
    'EdDSA',$3::jsonb,'synthetic-local-projection-key',transaction_timestamp()-interval '1 minute')`,
    [keyId, actor.organizationId, JSON.stringify(publicJwk), keyKid]
  );
  await pool.query(
    `insert into clock_health_samples(id,organization_id,source,measured_at,
    drift_microseconds,valid_until) values($1,$2,'synthetic-projection',transaction_timestamp(),0,
    transaction_timestamp()+interval '5 minutes')`,
    [clockId, actor.organizationId]
  );
  const payload =
    suppliedDraft?.canonicalPayload ??
    jsonBytes({ syntheticStorageFixture: true, voteId, certificateId });
  const tallyHash = hash(jsonBytes(JSON.parse(tallyJson)));
  const client = await pool.connect();
  try {
    await client.query("begin");
    const opened = await client.query(
      `update votes as vote set state='open',
      opened_at=transaction_timestamp(),deadline_at=transaction_timestamp()+interval '1 day',
      electorate_sha256=package.electorate_sha256,matter_evaluation_id=package.matter_evaluation_id,
      selected_ruleset_rule_id=package.selected_ruleset_rule_id,row_version=vote.row_version+1
      from decision_packages as package where vote.id=$1 and vote.state='draft'
        and package.id=vote.current_decision_package_id and package.id=$2 returning vote.id`,
      [voteId, bound.package_id]
    );
    if (opened.rowCount !== 1)
      throw new Error("outcome fixture could not open its exact draft row");
    await client.query(
      `insert into vote_outcomes(id,organization_id,board_id,vote_id,
      decision_package_id,electorate_sha256,approval_rule_id,canonical_tally,tally_sha256,outcome,
      close_mode,close_actor_member_id,close_consent_record_id,certificate_id,certificate_public_id,
      canonical_certificate_payload,certificate_payload_sha256,signing_key_id,clock_sample_id,
      closing_audit_event_id,close_request_sha256)
      select $1,vote.organization_id,vote.board_id,vote.id,vote.current_decision_package_id,
        vote.electorate_sha256,vote.approval_rule_id,$2::jsonb,$3,'approved',vote.close_mode,
        $4,$5,$6,$7,$8,$9,$10,$11,$12,$13 from votes as vote where vote.id=$14`,
      [
        outcomeId,
        tallyJson,
        tallyHash,
        actor.memberId,
        evidence.consent,
        certificateId,
        suppliedDraft?.publicId ?? hash("synthetic-vote-projection-public-id"),
        payload,
        hash(payload),
        keyId,
        clockId,
        evidence.audit,
        evidence.digest,
        voteId
      ]
    );
    const closing = await client.query(
      `update votes set state='closing',row_version=row_version+1
      where id=$1 and state='open' returning id`,
      [voteId]
    );
    if (closing.rowCount !== 1)
      throw new Error("outcome fixture could not retain its required closing state");
    await client.query("commit");
  } catch (error) {
    await client.query("rollback");
    throw error;
  } finally {
    client.release();
  }
  return { outcomeId, certificateId, signingKeyId: keyId, tallyHash };
}
