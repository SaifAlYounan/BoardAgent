import { createHash } from "node:crypto";
import type { Pool } from "pg";
import { expect } from "vitest";
import {
  PgBoardAgentSurfaceService,
  type SurfacePrincipal
} from "../../artifacts/server/src/index.js";
import {
  TOOL_INPUT_SCHEMA_VERSION,
  sha256Hex,
  canonicalJson,
  type JsonValue
} from "../../lib/contracts/src/index.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import { appendAuditEventsInTransaction } from "../../lib/db/src/transactions/audit.js";
import {
  seedAuthorizedActor,
  seedAdditionalAuthorizedActor,
  testId,
  type AuthorizedActorFixture
} from "./authorized-actor.js";

// In-process confirmations of ONLY the named minutes actions. No broad source
// test is imported; no task/pending-feed/worker route exists in this fixture.
const allowed = new Set([
  "publish_minutes",
  "declare_no_minutes_action_items",
  "prepare_minutes_for_signature",
  "stage_minutes_signature",
  "finalize_minutes",
  "create_minutes_correction_cycle",
  "resolve_minutes_review_item",
  "correct_minutes_package"
]);
function principal(
  actor: AuthorizedActorFixture,
  role: "member" | "secretariat"
): SurfacePrincipal {
  return {
    organizationId: actor.organizationId,
    memberId: actor.memberId,
    serviceOrigin: "https://boardagent.test",
    clientId: actor.clientId,
    protocolClientId: `https://${role}-agent.test/client.json`,
    accessTokenRecordId: actor.accessTokenRecordId,
    tokenJti: actor.tokenJti,
    keyId: "test-oauth",
    scopes:
      role === "secretariat"
        ? ["minutes:act", "secretariat:admin", "governance:read"]
        : ["minutes:act", "governance:read"],
    roles: [role],
    boardIds: [actor.boardId]
  };
}
export async function seedMinutesLineageFixture(pool: Pool) {
  const secretary = await seedAuthorizedActor(pool, {
    seatRole: "voting_member",
    isSecretary: true,
    scopes: ["minutes:act", "secretariat:admin", "governance:read"]
  });
  const signer = await seedAdditionalAuthorizedActor(pool, secretary, {
    idBase: 330_000,
    seatRole: "voting_member",
    scopes: ["minutes:act", "governance:read"]
  });
  const meetingId = testId(331_000),
    originalId = testId(331_001),
    middleId = testId(331_002),
    replacementId = testId(331_003);
  const originalText = "# Minutes\nSynthetic lineage root.\n",
    middleText = "# Minutes\nSynthetic first correction.\n",
    replacementText = "# Minutes\nSynthetic next correction.\n";
  await pool.query(
    `insert into meetings(id,organization_id,board_id,title,state,scheduled_start,scheduled_end,created_by)
    values($1,$2,$3,'Synthetic lineage meeting','called',transaction_timestamp()+interval '1 hour',transaction_timestamp()+interval '2 hours',$4)`,
    [meetingId, secretary.organizationId, secretary.boardId, secretary.memberId]
  );
  let next = 332_000,
    sequence = 0;
  const commands: string[] = [];
  const service = new PgBoardAgentSurfaceService(pool, {
    reads: {
      executeRead: async () => {
        throw new Error("fixture has no read route");
      },
      readResource: async () => {
        throw new Error("fixture has no resource route");
      }
    },
    transaction: { assumeRole: "boardagent_server" },
    newId: () => testId(next++)
  });
  async function confirm(
    actor: AuthorizedActorFixture,
    role: "member" | "secretariat",
    tool: string,
    input: JsonValue
  ) {
    if (!allowed.has(tool)) throw new Error("out-of-scope lineage fixture action");
    const actorPrincipal = principal(actor, role),
      label = `lineage-${++sequence}-${tool}`;
    const prepared = await service.prepareHumanAction(actorPrincipal, tool, input);
    expect(prepared).toMatchObject({ action_code: tool, target_type: "minutes" });
    const capabilities = { elicitation: { form: {} } } as const,
      requestState = `synthetic-minutes-lineage-request-state-${label}`;
    await service.persistHumanStage({
      principal: actorPrincipal,
      tool,
      input,
      prepared,
      client_capabilities: capabilities,
      embedded_form: { type: "object", required: ["approve", "confirmation_code"] },
      embedded_result: { message: `Confirm exact ${tool}` },
      request_state: requestState,
      prepared_request_id: Buffer.from(`${label}-prepare`)
    });
    const resolved = await service.resolveHumanAction({
      principal: actorPrincipal,
      tool,
      input,
      stage_id: prepared.stage_id,
      client_capabilities: capabilities,
      request_state: requestState,
      retry_request_id: Buffer.from(`${label}-retry`),
      response_action: "accept",
      input_response: { approve: true, confirmation_code: prepared.confirmation_code }
    });
    if (!resolved.confirmed) throw new Error(`${tool} refused: ${resolved.reason}`);
    expect(resolved.result.status).toBe("accepted");
    commands.push(tool);
    return resolved.result;
  }
  const draft = await service.executeDirect(
    principal(secretary, "secretariat"),
    "create_minutes_version",
    {
      schema_version: TOOL_INPUT_SCHEMA_VERSION,
      minutes_id: originalId,
      meeting_id: meetingId,
      canonical_text: originalText,
      transcript_version_id: null,
      expected_current_version_id: null,
      idempotency_key: "lineage-initial-draft-0001"
    }
  );
  expect(draft.status).toBe("accepted");
  if (!draft.reference) throw new Error("lineage draft reference absent");
  commands.push("create_minutes_version");
  await confirm(secretary, "secretariat", "publish_minutes", {
    schema_version: TOOL_INPUT_SCHEMA_VERSION,
    minutes_id: originalId,
    version_id: draft.reference,
    minutes_sha256: sha256Hex(originalText),
    signer_member_ids: [signer.memberId],
    idempotency_key: "lineage-initial-publish-0001"
  });
  async function finalize(minutesId: string, text: string) {
    const row = (
      await pool.query<{ id: string; version: number; state: string }>(
        `select version.id,version.version,minutes.state
      from minutes join minutes_versions as version on version.id=minutes.current_version_id where minutes.id=$1`,
        [minutesId]
      )
    ).rows[0];
    if (!row) throw new Error("lineage current version absent");
    expect(row.state).toBe("published_review");
    await confirm(secretary, "secretariat", "declare_no_minutes_action_items", {
      schema_version: TOOL_INPUT_SCHEMA_VERSION,
      manifest: {
        schemaVersion: "boardagent.minutes-action-manifest.v1",
        minutesId,
        minutesVersion: row.version,
        minutesSha256: sha256Hex(text),
        declaration: "no_action_items"
      },
      idempotency_key: `lineage-no-actions-${minutesId}`
    });
    const issued = await confirm(secretary, "secretariat", "prepare_minutes_for_signature", {
      schema_version: TOOL_INPUT_SCHEMA_VERSION,
      minutes_id: minutesId,
      expected_version_id: row.id,
      signer_member_ids: [signer.memberId],
      idempotency_key: `lineage-prepare-signature-${minutesId}`
    });
    if (!issued.reference) throw new Error("lineage signature package absent");
    await confirm(signer, "member", "stage_minutes_signature", {
      schema_version: TOOL_INPUT_SCHEMA_VERSION,
      minutes_id: minutesId,
      package_id: issued.reference,
      reservation: null,
      idempotency_key: `lineage-signature-${minutesId}`
    });
    await confirm(secretary, "secretariat", "finalize_minutes", {
      schema_version: TOOL_INPUT_SCHEMA_VERSION,
      minutes_id: minutesId,
      package_id: issued.reference,
      idempotency_key: `lineage-finalize-${minutesId}`
    });
    expect((await pool.query("select state from minutes where id=$1", [minutesId])).rows).toEqual([
      { state: "finalized" }
    ]);
  }
  async function correct(original: string, replacement: string, text: string, reason: string) {
    const result = await confirm(secretary, "secretariat", "create_minutes_correction_cycle", {
      schema_version: TOOL_INPUT_SCHEMA_VERSION,
      minutes_id: original,
      replacement_minutes_id: replacement,
      canonical_text: text,
      reason,
      idempotency_key: `lineage-correction-${replacement}`
    });
    expect(result.reference).toBe(replacement);
    const rows = (await pool.query("select id,state from minutes where id=$1", [replacement])).rows;
    expect(rows).toEqual([{ id: replacement, state: "published_review" }]);
    expect(
      (await pool.query("select current_minutes_id from meetings where id=$1", [meetingId])).rows
    ).toEqual([{ current_minutes_id: replacement }]);
  }
  await finalize(originalId, originalText);
  await correct(originalId, middleId, middleText, 'First "correction" Δ\\path');
  await finalize(middleId, middleText);
  let appended = false;
  let successorFinalized = false;
  let successorFinalizationStarted = false;
  let listsStarted = false;
  let listText = replacementText;
  let reviewIds: { firstComment: string; secondComment: string; redline: string } | null = null;
  let firstWithdrawn = false,
    secondWithdrawn = false,
    redlineResolved = false,
    corrections = 0;
  async function listCurrentVersion() {
    if (!appended || successorFinalized || successorFinalizationStarted)
      throw new Error("minutes list setup requires the published successor outside finalization");
    const row = (
      await pool.query<{ id: string; version: number; sha256: string; state: string }>(
        `select version.id,version.version,encode(version.canonical_sha256,'hex') as sha256,minutes.state
       from minutes join minutes_versions as version on version.id=minutes.current_version_id
       where minutes.id=$1`,
        [replacementId]
      )
    ).rows[0];
    if (!row) throw new Error("minutes list current version absent");
    expect(row.state).toBe("published_review");
    expect(row.sha256).toBe(sha256Hex(listText));
    return row;
  }
  async function withdrawListComment(which: "first" | "second") {
    await listCurrentVersion();
    if (!reviewIds || (which === "first" ? firstWithdrawn : secondWithdrawn))
      throw new Error("minutes list comment must exist and not already be withdrawn");
    const result = await service.executeDirect(
      principal(signer, "member"),
      "withdraw_minutes_comment",
      {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        minutes_id: replacementId,
        review_item_id: which === "first" ? reviewIds.firstComment : reviewIds.secondComment,
        idempotency_key: `minutes-list-withdraw-${which}-0001`
      }
    );
    expect(result.status).toBe("accepted");
    commands.push("withdraw_minutes_comment");
    if (which === "first") firstWithdrawn = true;
    else secondWithdrawn = true;
    return result;
  }
  const minutesLists = {
    seedReviews: async () => {
      if (listsStarted) throw new Error("minutes list review setup is one-shot");
      listsStarted = true;
      const current = await listCurrentVersion();
      expect(current.version).toBe(1);
      const base = {
        minutesId: replacementId,
        baseVersion: current.version,
        baseSha256: current.sha256
      };
      const ids: string[] = [];
      for (const [index, comment] of [
        'Synthetic "permit" comment Δ.',
        "Synthetic second comment 🙂."
      ].entries()) {
        const result = await service.executeDirect(principal(signer, "member"), "comment_minutes", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          payload: {
            schemaVersion: "boardagent.minutes-comment.v1",
            ...base,
            comment,
            citations: []
          },
          idempotency_key: `minutes-list-comment-${String(index)}-0001`
        });
        expect(result.status).toBe("accepted");
        if (!result.reference) throw new Error("minutes list comment reference absent");
        ids.push(result.reference);
        commands.push("comment_minutes");
      }
      const proposed = await service.executeDirect(
        principal(signer, "member"),
        "propose_minutes_redline",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          payload: {
            schemaVersion: "boardagent.minutes-redline.v1",
            ...base,
            anchor: { kind: "lines", startLine: 2, endLine: 2 },
            anchoredTextSha256: sha256Hex("Synthetic next correction."),
            operation: "replace",
            proposedText: "Synthetic clarified correction.",
            rationale: "Synthetic permit wording clarification.",
            citations: []
          },
          idempotency_key: "minutes-list-redline-0001"
        }
      );
      expect(proposed.status).toBe("accepted");
      if (!proposed.reference || !ids[0] || !ids[1])
        throw new Error("minutes list review references absent");
      commands.push("propose_minutes_redline");
      reviewIds = { firstComment: ids[0], secondComment: ids[1], redline: proposed.reference };
      return { ...reviewIds, version: current };
    },
    withdrawFirstComment: () => withdrawListComment("first"),
    withdrawSecondComment: () => withdrawListComment("second"),
    resolveRedline: async () => {
      const current = await listCurrentVersion();
      if (!reviewIds || redlineResolved)
        throw new Error("minutes list redline must exist and be unresolved");
      const result = await confirm(secretary, "secretariat", "resolve_minutes_review_item", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        minutes_id: replacementId,
        review_item_id: reviewIds.redline,
        disposition: "reject",
        reason: 'Synthetic rejection: retain original "permit" wording Δ.',
        replacement_text: null,
        idempotency_key: "minutes-list-reject-redline-0001"
      });
      expect(result.data).toMatchObject({ decision: "rejected", minutes_version_id: current.id });
      redlineResolved = true;
      return result;
    },
    appendVersion: async () => {
      const current = await listCurrentVersion();
      if (!reviewIds || !firstWithdrawn || !secondWithdrawn || !redlineResolved || corrections >= 2)
        throw new Error(
          "minutes list correction requires closed review items and at most two corrections"
        );
      const ordinal = corrections + 1;
      const nextText = `${listText}\n# List correction ${String(ordinal)}\nSynthetic permit wording.\n`;
      const result = await confirm(secretary, "secretariat", "correct_minutes_package", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        minutes_id: replacementId,
        expected_version_id: current.id,
        canonical_text: nextText,
        reason: `Synthetic list correction ${String(ordinal)}.`,
        idempotency_key: `minutes-list-correction-${String(ordinal)}-0001`
      });
      if (!result.reference) throw new Error("minutes list corrected version reference absent");
      listText = nextText;
      corrections = ordinal;
      const updated = await listCurrentVersion();
      expect(updated.id).toBe(result.reference);
      expect(updated.version).toBe(current.version + 1);
      return updated;
    }
  };
  return {
    secretary,
    signer,
    meetingId,
    originalId,
    middleId,
    replacementId,
    commands,
    minutesLists,
    currentTip: () => ({
      minutesId: appended ? replacementId : middleId,
      state: appended && !successorFinalized ? "published_review" : "finalized"
    }),
    appendSuccessor: async () => {
      if (appended) throw new Error("lineage successor already appended");
      await correct(middleId, replacementId, replacementText, "Second correction 🙂\nNew line.");
      appended = true;
    },
    finalizeSuccessor: async () => {
      if (!appended || successorFinalized || successorFinalizationStarted || listsStarted)
        throw new Error(
          "lineage successor must be appended, not finalized, and outside the list-review workflow"
        );
      successorFinalizationStarted = true;
      await finalize(replacementId, replacementText);
      successorFinalized = true;
    }
  };
}
const hash = (bytes: Uint8Array | string) => createHash("sha256").update(bytes).digest();
const jsonBytes = (value: unknown) => Buffer.from(canonicalJson(value), "utf8");
// Constrained synthetic exclusion evidence, reused from the passed canonical
// resource fixture. This is NOT a public recusal/confirmation ceremony.
async function recusalEvidence(
  pool: Pool,
  actor: AuthorizedActorFixture,
  target: {
    id: string;
    type: "minutes";
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

export async function excludeMinutesLineageEndpoint(
  pool: Pool,
  actor: AuthorizedActorFixture,
  minutesId: string,
  idBase: number
) {
  const evidence = await recusalEvidence(pool, actor, { id: minutesId, type: "minutes", idBase });
  const inserted = await pool.query(
    `insert into minutes_exclusions(id,organization_id,board_id,minutes_id,member_id,version,
    state,reason,actor_member_id,consent_record_id,audit_event_id)
    values($1,$2,$3,$4,$5,1,'excluded','Synthetic lineage storage recusal',$5,$6,$7) returning id`,
    [
      testId(idBase + 4),
      actor.organizationId,
      actor.boardId,
      minutesId,
      actor.memberId,
      evidence.consent,
      evidence.audit
    ]
  );
  expect(inserted.rows).toEqual([{ id: testId(idBase + 4) }]);
}
