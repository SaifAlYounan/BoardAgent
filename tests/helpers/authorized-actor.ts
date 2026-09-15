import { createHash } from "node:crypto";
import type { Pool } from "pg";

export const testId = (suffix: number): string =>
  `018f0000-0000-7000-8000-${suffix.toString(16).padStart(12, "0")}`;
export const testHash = (byte: number): Buffer => Buffer.alloc(32, byte);

export interface AuthorizedActorFixture {
  readonly organizationId: string;
  readonly boardId: string;
  readonly memberId: string;
  readonly clientId: string;
  readonly tokenJti: string;
  readonly accessTokenRecordId: string;
  readonly consentRecordId: string;
  readonly supportVersionId: string;
  readonly context: {
    readonly organizationId: string;
    readonly memberId: string;
    readonly clientId: string;
    readonly tokenJti: string;
    readonly boardIds: readonly string[];
  };
}

export async function seedAuthorizedActor(
  pool: Pool,
  options: {
    readonly seatRole: "voting_member" | "management" | "observer";
    readonly scopes: readonly string[];
    readonly isSecretary?: boolean;
  }
): Promise<AuthorizedActorFixture> {
  const organizationId = testId(1);
  const boardId = testId(2);
  const memberId = testId(3);
  const membershipId = testId(4);
  const supportVersionId = testId(5);
  const termsVersionId = testId(6);
  const clientId = testId(7);
  const signingKeyId = testId(8);
  const accessTokenRecordId = testId(9);
  const stageId = testId(10);
  const inputRequiredAttemptId = testId(11);
  const consentRecordId = testId(12);
  const attestationId = testId(13);
  const tokenJti = testId(14);
  const votingWeight = options.seatRole === "voting_member" ? 1 : 0;

  await pool.query(
    "insert into organizations(id,legal_name,display_name,slug,timezone) values ($1,'Org','Org','org','UTC')",
    [organizationId]
  );
  await pool.query(
    "insert into members(id,organization_id,member_kind,legal_name,display_name,state) values ($1,$2,'human','Actor','Actor','active')",
    [memberId, organizationId]
  );
  await pool.query(
    "insert into boards(id,organization_id,slug,name,timezone) values ($1,$2,'board','Board','UTC')",
    [boardId, organizationId]
  );
  await pool.query(
    "insert into system_instance(instance_id,organization_id,canonical_resource_uri) values ($1,$2,'https://boardagent.test/mcp')",
    [testId(15), organizationId]
  );
  await pool.query(
    `insert into board_memberships(
       id,organization_id,board_id,member_id,seat_role,is_secretary,voting_weight,state
     ) values ($1,$2,$3,$4,$5,$6,$7,'active')`,
    [
      membershipId,
      organizationId,
      boardId,
      memberId,
      options.seatRole,
      options.isSecretary ?? false,
      votingWeight
    ]
  );
  await pool.query(
    `insert into secretary_support_versions(
       id,organization_id,board_id,version,support_name,contact_methods,canonical_sha256,
       effective_at,created_by
     ) values ($1,$2,$3,1,'Board secretary','[]',$4,
       transaction_timestamp() - interval '1 minute',$5)`,
    [supportVersionId, organizationId, boardId, testHash(1), memberId]
  );
  await pool.query(
    `insert into onboarding_terms_versions(
       id,organization_id,seat_role,version,schema_version,canonical_text,canonical_sha256,
       material_change,effective_at,created_by
     ) values ($1,$2,$3,1,'boardagent.onboarding-terms.v1','Terms',$4,true,
       transaction_timestamp() - interval '1 minute',$5)`,
    [termsVersionId, organizationId, options.seatRole, testHash(2), memberId]
  );
  await pool.query(
    `insert into oauth_clients(
       id,organization_id,protocol_id_kind,protocol_id_value,safe_metadata,metadata_sha256,
       state,registered_by
     ) values ($1,$2,'preregistered','authorized-test-client','{}',$3,'active',$4)`,
    [clientId, organizationId, testHash(3), memberId]
  );
  await pool.query(
    `insert into crypto_key_registry(
       id,organization_id,kid,purpose,algorithm,public_jwk,nonsecret_locator,activated_at
     ) values ($1,$2,'test-oauth','oauth_signing','ES256','{}','local-test-key',
       transaction_timestamp() - interval '1 minute')`,
    [signingKeyId, organizationId]
  );
  await pool.query(
    `insert into access_token_records(
       id,organization_id,jti,member_id,client_id,resource_uri,scope_set,signing_key_id,
       expires_at
     ) values ($1,$2,$3,$4,$5,'https://boardagent.test/mcp',$6,$7,
       transaction_timestamp() + interval '10 minutes')`,
    [
      accessTokenRecordId,
      organizationId,
      tokenJti,
      memberId,
      clientId,
      [...options.scopes],
      signingKeyId
    ]
  );
  await pool.query(
    `insert into action_stages(
       id,organization_id,board_id,actor_member_id,action_code,target_type,target_id,
       canonical_schema,canonicalization_version,canonical_payload,payload_sha256,
       nonce_sha256,protected_code_sha256,client_id,access_token_record_id,token_jti,
       exact_origin,context_sha256,expires_at
     ) values (
       $1,$2,$3,$4,'prepare_onboarding_attestation','member',$4,
       'boardagent.onboarding-attestation.v1','RFC8785+NFC-LF-v1',$5,$6,$7,$8,$9,$10,$11,
       'https://client.example',$12,transaction_timestamp() + interval '10 minutes'
     )`,
    [
      stageId,
      organizationId,
      boardId,
      memberId,
      Buffer.from("{}"),
      testHash(4),
      testHash(5),
      testHash(6),
      clientId,
      accessTokenRecordId,
      tokenJti,
      testHash(7)
    ]
  );
  await pool.query(
    `insert into input_required_attempts(
       id,organization_id,stage_id,protocol_version,protocol_header_version,
       result_meta_version,original_method,original_name,original_arguments_sha256,
       capabilities_sha256,embedded_form_sha256,embedded_result_sha256,request_state_bytes,
       request_state_sha256,prepared_request_id
     ) values (
       $1,$2,$3,'2026-07-28','2026-07-28','boardagent.mrtr.v1','tools/call',
       'prepare_onboarding_attestation',$4,$5,$6,$7,$8,$9,$10
     )`,
    [
      inputRequiredAttemptId,
      organizationId,
      stageId,
      testHash(8),
      testHash(9),
      testHash(10),
      testHash(11),
      Buffer.alloc(32, 12),
      testHash(12),
      Buffer.from("request-1")
    ]
  );
  await pool.query(
    `insert into consent_records(
       id,organization_id,board_id,stage_id,input_required_attempt_id,actor_member_id,
       action_code,target_type,target_id,canonical_schema,payload_sha256,
       protected_code_record_sha256,access_token_record_id,token_jti,client_id,exact_origin,
       staged_at,record_sha256
     ) values (
       $1,$2,$3,$4,$5,$6,'prepare_onboarding_attestation','member',$6,
       'boardagent.consent-record.v1',$7,$8,$9,$10,$11,'https://client.example',
       transaction_timestamp(),$12
     )`,
    [
      consentRecordId,
      organizationId,
      boardId,
      stageId,
      inputRequiredAttemptId,
      memberId,
      testHash(13),
      testHash(14),
      accessTokenRecordId,
      tokenJti,
      clientId,
      testHash(15)
    ]
  );
  await pool.query(
    `insert into onboarding_attestations(
       id,organization_id,member_id,board_id,terms_version_id,support_version_id,
       presentation_choice,local_memory_choice,consent_record_id
     ) values ($1,$2,$3,$4,$5,$6,'structured','local-only',$7)`,
    [
      attestationId,
      organizationId,
      memberId,
      boardId,
      termsVersionId,
      supportVersionId,
      consentRecordId
    ]
  );

  return {
    organizationId,
    boardId,
    memberId,
    clientId,
    tokenJti,
    accessTokenRecordId,
    consentRecordId,
    supportVersionId,
    context: { organizationId, memberId, clientId, tokenJti, boardIds: [boardId] }
  };
}

export async function seedAdditionalAuthorizedActor(
  pool: Pool,
  board: Pick<
    AuthorizedActorFixture,
    "organizationId" | "boardId" | "memberId" | "supportVersionId"
  >,
  options: {
    readonly idBase: number;
    readonly seatRole: "voting_member" | "management" | "observer";
    readonly scopes: readonly string[];
    readonly isSecretary?: boolean;
    readonly uniqueHashes?: boolean;
  }
): Promise<AuthorizedActorFixture> {
  const id = (offset: number) => testId(options.idBase + offset);
  const hash = (offset: number) =>
    options.uniqueHashes
      ? createHash("sha256").update(`synthetic-actor:${options.idBase}:${offset}`).digest()
      : testHash((options.idBase + offset) % 256);
  const memberId = id(1);
  const membershipId = id(2);
  const proposedTermsVersionId = id(3);
  const clientId = id(4);
  const signingKeyId = id(5);
  const accessTokenRecordId = id(6);
  const stageId = id(7);
  const inputRequiredAttemptId = id(8);
  const consentRecordId = id(9);
  const attestationId = id(10);
  const tokenJti = id(11);
  const votingWeight = options.seatRole === "voting_member" ? 1 : 0;

  await pool.query(
    "insert into members(id,organization_id,member_kind,legal_name,display_name,state) values ($1,$2,'human','Additional actor','Additional actor','active')",
    [memberId, board.organizationId]
  );
  await pool.query(
    `insert into board_memberships(
       id,organization_id,board_id,member_id,seat_role,is_secretary,voting_weight,state
     ) values ($1,$2,$3,$4,$5,$6,$7,'active')`,
    [
      membershipId,
      board.organizationId,
      board.boardId,
      memberId,
      options.seatRole,
      options.isSecretary ?? false,
      votingWeight
    ]
  );
  await pool.query(
    `insert into onboarding_terms_versions(
       id,organization_id,seat_role,version,schema_version,canonical_text,canonical_sha256,
       material_change,effective_at,created_by
     ) values ($1,$2,$3,1,'boardagent.onboarding-terms.v1','Terms',$4,true,
       transaction_timestamp() - interval '1 minute',$5)
     on conflict (organization_id,seat_role,version) do nothing`,
    [proposedTermsVersionId, board.organizationId, options.seatRole, hash(21), board.memberId]
  );
  const terms = await pool.query<{ id: string }>(
    `select id from onboarding_terms_versions
      where organization_id=$1 and seat_role=$2 and version=1`,
    [board.organizationId, options.seatRole]
  );
  const termsVersionId = terms.rows[0]?.id;
  if (!termsVersionId) throw new Error("test onboarding terms version is unavailable");
  await pool.query(
    `insert into oauth_clients(
       id,organization_id,protocol_id_kind,protocol_id_value,safe_metadata,metadata_sha256,
       state,registered_by
     ) values ($1,$2,'preregistered',$3,'{}',$4,'active',$5)`,
    [
      clientId,
      board.organizationId,
      `authorized-test-client-${String(options.idBase)}`,
      hash(22),
      memberId
    ]
  );
  await pool.query(
    `insert into crypto_key_registry(
       id,organization_id,kid,purpose,algorithm,public_jwk,nonsecret_locator,activated_at
     ) values ($1,$2,$3,'oauth_signing','ES256','{}',$4,
       transaction_timestamp() - interval '1 minute')`,
    [
      signingKeyId,
      board.organizationId,
      `test-oauth-${String(options.idBase)}`,
      `local-test-key-${String(options.idBase)}`
    ]
  );
  await pool.query(
    `insert into access_token_records(
       id,organization_id,jti,member_id,client_id,resource_uri,scope_set,signing_key_id,
       expires_at
     ) values ($1,$2,$3,$4,$5,'https://boardagent.test/mcp',$6,$7,
       transaction_timestamp() + interval '10 minutes')`,
    [
      accessTokenRecordId,
      board.organizationId,
      tokenJti,
      memberId,
      clientId,
      [...options.scopes],
      signingKeyId
    ]
  );
  await pool.query(
    `insert into action_stages(
       id,organization_id,board_id,actor_member_id,action_code,target_type,target_id,
       canonical_schema,canonicalization_version,canonical_payload,payload_sha256,
       nonce_sha256,protected_code_sha256,client_id,access_token_record_id,token_jti,
       exact_origin,context_sha256,expires_at
     ) values (
       $1,$2,$3,$4,'prepare_onboarding_attestation','member',$4,
       'boardagent.onboarding-attestation.v1','RFC8785+NFC-LF-v1',$5,$6,$7,$8,$9,$10,$11,
       'https://client.example',$12,transaction_timestamp() + interval '10 minutes'
     )`,
    [
      stageId,
      board.organizationId,
      board.boardId,
      memberId,
      Buffer.from("{}"),
      hash(23),
      hash(24),
      hash(25),
      clientId,
      accessTokenRecordId,
      tokenJti,
      hash(26)
    ]
  );
  await pool.query(
    `insert into input_required_attempts(
       id,organization_id,stage_id,protocol_version,protocol_header_version,
       result_meta_version,original_method,original_name,original_arguments_sha256,
       capabilities_sha256,embedded_form_sha256,embedded_result_sha256,request_state_bytes,
       request_state_sha256,prepared_request_id
     ) values (
       $1,$2,$3,'2026-07-28','2026-07-28','boardagent.mrtr.v1','tools/call',
       'prepare_onboarding_attestation',$4,$5,$6,$7,$8,$9,$10
     )`,
    [
      inputRequiredAttemptId,
      board.organizationId,
      stageId,
      hash(27),
      hash(28),
      hash(29),
      hash(30),
      hash(31),
      hash(32),
      Buffer.from(`request-${String(options.idBase)}`)
    ]
  );
  await pool.query(
    `insert into consent_records(
       id,organization_id,board_id,stage_id,input_required_attempt_id,actor_member_id,
       action_code,target_type,target_id,canonical_schema,payload_sha256,
       protected_code_record_sha256,access_token_record_id,token_jti,client_id,exact_origin,
       staged_at,record_sha256
     ) values (
       $1,$2,$3,$4,$5,$6,'prepare_onboarding_attestation','member',$6,
       'boardagent.consent-record.v1',$7,$8,$9,$10,$11,'https://client.example',
       transaction_timestamp(),$12
     )`,
    [
      consentRecordId,
      board.organizationId,
      board.boardId,
      stageId,
      inputRequiredAttemptId,
      memberId,
      hash(33),
      hash(34),
      accessTokenRecordId,
      tokenJti,
      clientId,
      hash(35)
    ]
  );
  await pool.query(
    `insert into onboarding_attestations(
       id,organization_id,member_id,board_id,terms_version_id,support_version_id,
       presentation_choice,local_memory_choice,consent_record_id
     ) values ($1,$2,$3,$4,$5,$6,'structured','local-only',$7)`,
    [
      attestationId,
      board.organizationId,
      memberId,
      board.boardId,
      termsVersionId,
      board.supportVersionId,
      consentRecordId
    ]
  );

  return {
    organizationId: board.organizationId,
    boardId: board.boardId,
    memberId,
    clientId,
    tokenJti,
    accessTokenRecordId,
    consentRecordId,
    supportVersionId: board.supportVersionId,
    context: {
      organizationId: board.organizationId,
      memberId,
      clientId,
      tokenJti,
      boardIds: [board.boardId]
    }
  };
}
