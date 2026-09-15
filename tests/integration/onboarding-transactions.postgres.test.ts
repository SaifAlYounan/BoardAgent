import { confirmSyntheticSurfaceAction } from "../helpers/confirmed-surface-action.js";
import { dropClosedTestDatabase } from "../helpers/drop-test-database.js";
import { createHash } from "node:crypto";
import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import {
  BuiltinOnboardingError,
  BuiltinOnboardingService,
  PgBoardAgentSurfaceService,
  PgOnboardingBrowserStore,
  PgWebAuthnStore,
  WebAuthnCeremony,
  type SurfacePrincipal
} from "../../artifacts/server/src/index.js";
import { DirectReadRepository } from "../helpers/direct-response-allocation.js";
import {
  TOOL_INPUT_SCHEMA_VERSION,
  canonicalJson,
  canonicalSha256,
  type JsonValue
} from "../../lib/contracts/src/index.js";
import {
  migrate,
  withWorkerTransaction,
  inspectFeedConsistencyInTransaction
} from "../../lib/db/src/index.js";
import {
  AUTHENTICATION_CHALLENGE,
  CREDENTIAL_ID,
  allowAllWebAuthnAttempts,
  authenticationResponse,
  fakeWebAuthnCrypto,
  idSequence
} from "../browser/webauthn-harness.js";
import {
  seedAuthorizedActor,
  seedAdditionalAuthorizedActor,
  testHash,
  testId,
  type AuthorizedActorFixture
} from "../helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
const ORIGIN = "https://boardagent.test";
const SCOPES = ["governance:read", "onboarding:read"] as const;
let databaseCounter = 0;

interface RequiredOnboardingFixture {
  readonly actor: AuthorizedActorFixture;
  readonly credentialId: string;
  readonly principal: SurfacePrincipal;
  readonly sessionId: string;
  readonly termsVersionId: string;
}

async function withDatabase<T>(run: (owner: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_onboarding_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const ownerUrl = new URL(BASE_URL);
  ownerUrl.pathname = `/${database}`;
  const owner = new Pool({ connectionString: ownerUrl.toString(), max: 6 });
  try {
    await migrate(owner, MIGRATIONS, "onboarding-transactions-test");
    return await run(owner);
  } finally {
    await owner.end();
    await dropClosedTestDatabase(admin, database);
    await admin.end();
  }
}

async function seedRequiredOnboarding(
  owner: Pool,
  idBase: number,
  stale = true
): Promise<RequiredOnboardingFixture> {
  const actor = await seedAuthorizedActor(owner, {
    seatRole: "voting_member",
    scopes: SCOPES
  });
  const termsVersionId = stale ? testId(idBase + 1) : testId(6);
  const sessionId = testId(idBase + 2);
  const credentialId = testId(idBase + 3);
  if (stale)
    await owner.query(
      `insert into onboarding_terms_versions(
       id,organization_id,seat_role,version,schema_version,canonical_text,canonical_sha256,
       material_change,effective_at,created_by
     ) values ($1,$2,'voting_member',2,'boardagent.onboarding-terms.v1',
               'Director terms version two',$3,true,
               transaction_timestamp()-interval '1 second',$4)`,
      [termsVersionId, actor.organizationId, testHash(202), actor.memberId]
    );
  await owner.query(
    `insert into auth_sessions(
       id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,
       expires_at,last_authenticated_at
     ) values ($1,$2,$3,$4,$5,'authenticated',$6,
               transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
    [sessionId, actor.organizationId, testHash(203), actor.memberId, actor.clientId, ORIGIN]
  );
  await owner.query("update access_token_records set session_id=$1 where id=$2", [
    sessionId,
    actor.accessTokenRecordId
  ]);
  await owner.query(
    `insert into webauthn_credentials(
       id,organization_id,member_id,credential_id,public_key,signature_counter,transports,
       backup_eligible,backup_state,state
     ) values ($1,$2,$3,$4,$5,0,array['internal'],false,false,'active')`,
    [
      credentialId,
      actor.organizationId,
      actor.memberId,
      Buffer.from(CREDENTIAL_ID, "base64url"),
      Buffer.alloc(64, 7)
    ]
  );
  return {
    actor,
    credentialId,
    principal: {
      organizationId: actor.organizationId,
      memberId: actor.memberId,
      serviceOrigin: ORIGIN,
      clientId: actor.clientId,
      protocolClientId: "authorized-test-client",
      accessTokenRecordId: actor.accessTokenRecordId,
      tokenJti: actor.tokenJti,
      keyId: "test-oauth",
      scopes: SCOPES,
      roles: ["member"],
      boardIds: [actor.boardId]
    },
    sessionId,
    termsVersionId
  };
}

function record(value: JsonValue): Readonly<Record<string, JsonValue>> {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new TypeError("expected structured BoardAgent result data");
  }
  return value as Readonly<Record<string, JsonValue>>;
}

function stageArguments(fixture: RequiredOnboardingFixture, key: string) {
  return {
    schema_version: TOOL_INPUT_SCHEMA_VERSION,
    board_id: fixture.actor.boardId,
    terms_version_id: fixture.termsVersionId,
    support_version_id: fixture.actor.supportVersionId,
    presentation_choice: "structured summaries with source links",
    local_memory_choice: "encrypted local cache with tombstone processing",
    idempotency_key: key
  } as const;
}

function onboardingComponents(owner: Pool, idBase: number) {
  const reads = new DirectReadRepository(owner, {
    cursorKey: new Uint8Array(32).fill(0x73),
    transaction: { assumeRole: "boardagent_server" }
  });
  const surface = new PgBoardAgentSurfaceService(owner, {
    reads,
    transaction: { assumeRole: "boardagent_server" },
    entropy: (length) => Buffer.alloc(length, 0xe1),
    newId: idSequence(idBase)
  });
  const browserStore = new PgOnboardingBrowserStore(owner, {
    assumeRole: "boardagent_server"
  });
  const webauthnStore = new PgWebAuthnStore(owner, { assumeRole: "boardagent_server" });
  const ceremony = new WebAuthnCeremony({
    rpName: "BoardAgent",
    rpId: "boardagent.test",
    origin: ORIGIN,
    store: webauthnStore,
    attemptLimiter: allowAllWebAuthnAttempts,
    crypto: fakeWebAuthnCrypto().crypto,
    newId: idSequence(idBase + 100)
  });
  const onboarding = new BuiltinOnboardingService({
    organizationId: testId(1),
    store: browserStore,
    webauthn: ceremony,
    newId: idSequence(idBase + 200)
  });
  return { browserStore, ceremony, onboarding, reads, surface, webauthnStore };
}

async function insertPendingOnboardingAction(
  owner: Pool,
  fixture: RequiredOnboardingFixture,
  auditEventId: string,
  idBase: number
): Promise<string> {
  const pendingId = testId(idBase);
  const payload = {
    schemaVersion: "boardagent.pending-onboarding.v1",
    memberId: fixture.actor.memberId
  } as const;
  await owner.query(
    `insert into pending_action_feed(
       id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
       action_type,object_type,object_id,object_version,visibility_sha256,
       canonical_payload,payload_sha256,audit_event_id
     ) values ($1,$2,$3,$4,1,1,'complete_onboarding','member',$4,2,$5,$6,$7,$8)`,
    [
      pendingId,
      fixture.actor.organizationId,
      fixture.actor.boardId,
      fixture.actor.memberId,
      testHash(204),
      Buffer.from(canonicalJson(payload), "utf8"),
      Buffer.from(canonicalSha256(payload), "hex"),
      auditEventId
    ]
  );
  return pendingId;
}

describe("browser/passkey onboarding authority", () => {
  it("MR-ONBOARDING-001 refuses a staged browser read after confirmed board recusal and permits it after lift", async () => {
    await withDatabase(async (owner) => {
      const fixture = await seedRequiredOnboarding(owner, 99_000);
      // Current synthetic management secretary; only the voting member needs new terms.
      const secretaryScopes = ["governance:read", "secretariat:admin"];
      const secretary = await seedAdditionalAuthorizedActor(owner, fixture.actor, {
        idBase: 100_000,
        seatRole: "management",
        isSecretary: true,
        scopes: secretaryScopes,
        uniqueHashes: true
      });
      const secretarySessionId = testId(100_100);
      await owner.query(
        `insert into auth_sessions(
           id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,
           expires_at,last_authenticated_at
         ) values ($1,$2,$3,$4,$5,'authenticated',$6,
                   transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
        [
          secretarySessionId,
          secretary.organizationId,
          createHash("sha256").update("synthetic-onboarding-recusal-secretary-session").digest(),
          secretary.memberId,
          secretary.clientId,
          ORIGIN
        ]
      );
      await owner.query("update access_token_records set session_id=$1 where id=$2", [
        secretarySessionId,
        secretary.accessTokenRecordId
      ]);
      const secretaryPrincipal: SurfacePrincipal = {
        ...fixture.principal,
        memberId: secretary.memberId,
        clientId: secretary.clientId,
        accessTokenRecordId: secretary.accessTokenRecordId,
        tokenJti: secretary.tokenJti,
        protocolClientId: "authorized-test-client-100000",
        scopes: secretaryScopes,
        roles: ["member", "secretariat"]
      };
      const components = onboardingComponents(owner, 101_000);
      let recusalEntropySequence = 0;
      const recusalSurface = new PgBoardAgentSurfaceService(owner, {
        reads: components.reads,
        transaction: { assumeRole: "boardagent_server" },
        newId: idSequence(103_000),
        entropy: (length) => Buffer.alloc(length, ++recusalEntropySequence)
      });
      const crypto = fakeWebAuthnCrypto().crypto;
      let challengeSequence = 0;
      const onboarding = new BuiltinOnboardingService({
        organizationId: fixture.actor.organizationId,
        store: components.browserStore,
        webauthn: new WebAuthnCeremony({
          rpName: "BoardAgent",
          rpId: "boardagent.test",
          origin: ORIGIN,
          store: components.webauthnStore,
          attemptLimiter: allowAllWebAuthnAttempts,
          newId: idSequence(102_000),
          crypto: {
            ...crypto,
            generateAuthenticationOptions: async (options) => ({
              ...(await crypto.generateAuthenticationOptions(options)),
              challenge: Buffer.alloc(32, ++challengeSequence).toString("base64url")
            })
          }
        })
      });
      const prepared = await components.surface.executeDirect(
        fixture.principal,
        "prepare_onboarding_attestation",
        stageArguments(fixture, "onboarding-recusal-browser-read-0001")
      );
      expect(prepared.status).toBe("accepted");
      const stageToken = new URL(String(record(prepared.data)["onboarding_url"])).hash.slice(1);
      const stageTokenSha256 = createHash("sha256").update(stageToken).digest("hex");
      await expect(onboarding.begin({ stageToken })).resolves.toMatchObject({
        terms: { versionId: fixture.termsVersionId },
        secretarySupport: { versionId: fixture.actor.supportVersionId }
      });
      const recusalInput = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        board_id: fixture.actor.boardId,
        object_type: "board",
        object_id: fixture.actor.boardId,
        member_id: fixture.actor.memberId,
        operation: "add",
        reason: "Synthetic standing board conflict during an unfinished onboarding ceremony",
        idempotency_key: "onboarding-recusal-add-0001"
      } as const;
      const added = await confirmSyntheticSurfaceAction(
        recusalSurface,
        secretaryPrincipal,
        "manage_recusal",
        recusalInput
      );
      expect(added.result.data).toMatchObject({ state: "excluded" });
      const beforeDeniedRead = await owner.query(
        `select
           (select jsonb_agg(to_jsonb(c) order by c.id) from webauthn_challenges c
             where c.member_id=$1) as challenges,
           (select to_jsonb(s) from onboarding_browser_stages s where s.id=$2) as stage,
           (select to_jsonb(c) from webauthn_credentials c where c.id=$3) as credential`,
        [fixture.actor.memberId, prepared.reference, fixture.credentialId]
      );
      await expect(onboarding.begin({ stageToken })).rejects.toMatchObject({
        name: "BuiltinOnboardingError",
        code: "onboarding_unavailable",
        message: "onboarding ceremony is unavailable"
      });
      await expect(
        components.browserStore.findCandidate({
          organizationId: fixture.actor.organizationId,
          stageTokenSha256
        })
      ).resolves.toBeNull();
      expect(
        (
          await owner.query(
            `select
               (select jsonb_agg(to_jsonb(c) order by c.id) from webauthn_challenges c
                 where c.member_id=$1) as challenges,
               (select to_jsonb(s) from onboarding_browser_stages s where s.id=$2) as stage,
               (select to_jsonb(c) from webauthn_credentials c where c.id=$3) as credential`,
            [fixture.actor.memberId, prepared.reference, fixture.credentialId]
          )
        ).rows
      ).toEqual(beforeDeniedRead.rows);
      const lifted = await confirmSyntheticSurfaceAction(
        recusalSurface,
        secretaryPrincipal,
        "manage_recusal",
        { ...recusalInput, operation: "lift", idempotency_key: "onboarding-recusal-lift-0001" }
      );
      expect(lifted.result.data).toMatchObject({ state: "lifted" });
      await expect(onboarding.begin({ stageToken })).resolves.toMatchObject({
        terms: { versionId: fixture.termsVersionId },
        secretarySupport: { versionId: fixture.actor.supportVersionId }
      });
      expect(
        (
          await owner.query(
            "select version,state from board_exclusions where board_id=$1 and member_id=$2 order by version",
            [fixture.actor.boardId, fixture.actor.memberId]
          )
        ).rows
      ).toEqual([
        { version: 1, state: "excluded" },
        { version: 2, state: "lifted" }
      ]);
      expect(challengeSequence).toBe(2);
    });
  });

  it("completes a one-use staged URL and atomically records current onboarding", async () => {
    await withDatabase(async (owner) => {
      const fixture = await seedRequiredOnboarding(owner, 71_000);
      const components = onboardingComponents(owner, 71_100);
      const args = stageArguments(fixture, "onboarding-complete-0001");
      const prepared = await components.surface.executeDirect(
        fixture.principal,
        "prepare_onboarding_attestation",
        args
      );
      expect(prepared.status).toBe("accepted");
      const preparedData = record(prepared.data);
      const onboardingUrl = new URL(String(preparedData["onboarding_url"]));
      const stageToken = onboardingUrl.hash.slice(1);
      expect(onboardingUrl.origin + onboardingUrl.pathname).toBe(`${ORIGIN}/onboarding`);
      expect(stageToken).toHaveLength(43);
      expect(onboardingUrl.search).toBe("");

      const persistedStage = await owner.query<{
        created_audit_event_id: string;
        expires_in_seconds: string;
        id: string;
        stage_token_sha256: string;
        state: string;
      }>(
        `select id,state,created_audit_event_id,
                encode(stage_token_sha256,'hex') as stage_token_sha256,
                extract(epoch from expires_at-created_at)::text as expires_in_seconds
           from onboarding_browser_stages`
      );
      expect(persistedStage.rows).toHaveLength(1);
      const stage = persistedStage.rows[0]!;
      expect(stage).toMatchObject({
        id: prepared.reference,
        state: "active",
        expires_in_seconds: "600.000000"
      });
      expect(stage.stage_token_sha256).toBe(
        createHash("sha256").update(stageToken, "utf8").digest("hex")
      );
      expect(JSON.stringify(stage)).not.toContain(stageToken);

      const replay = await components.surface.executeDirect(
        fixture.principal,
        "prepare_onboarding_attestation",
        args
      );
      expect(replay.status).toBe("already_applied");
      expect(record(replay.data)["onboarding_url"]).toBeNull();
      await expect(
        components.surface.executeDirect(
          fixture.principal,
          "prepare_onboarding_attestation",
          stageArguments(fixture, "onboarding-parallel-0002")
        )
      ).rejects.toMatchObject({ code: "onboarding_stage_active" });

      await expect(
        components.browserStore.findCandidate({
          organizationId: fixture.actor.organizationId,
          stageTokenSha256: "00".repeat(32)
        })
      ).resolves.toBeNull();
      const begun = await components.onboarding.begin({ stageToken });
      expect(begun).toMatchObject({
        organizationDisplayName: "Org",
        boardName: "Board",
        memberDisplayName: "Actor",
        seatRole: "voting_member",
        terms: {
          versionId: fixture.termsVersionId,
          canonicalText: "Director terms version two"
        },
        secretarySupport: {
          versionId: fixture.actor.supportVersionId,
          name: "Board secretary"
        },
        presentationChoice: args.presentation_choice,
        localMemoryChoice: args.local_memory_choice
      });
      expect(begun.publicKey.challenge).toBe(AUTHENTICATION_CHALLENGE);
      expect(begun.publicKey.userVerification).toBe("required");

      const pendingId = await insertPendingOnboardingAction(
        owner,
        fixture,
        stage.created_audit_event_id,
        71_500
      );
      await expect(
        components.onboarding.complete({ stageToken, response: authenticationResponse })
      ).resolves.toEqual({
        status: "current",
        memberId: fixture.actor.memberId,
        boardId: fixture.actor.boardId,
        termsVersionId: fixture.termsVersionId,
        supportVersionId: fixture.actor.supportVersionId
      });

      const proof = await owner.query<{
        attestation_count: string;
        challenge_consumed: boolean;
        comprehension_claimed: boolean;
        consent_record_id: string | null;
        credential_counter: string;
        pending_state: string;
        stage_state: string;
        tombstone_count: string;
      }>(
        `select
           (select count(*)::text from onboarding_attestations
             where onboarding_browser_stage_id=$1 and consent_record_id is null)
             as attestation_count,
           (select state from onboarding_browser_stages where id=$1) as stage_state,
           (select consumed_at is not null from webauthn_challenges
             where purpose='recent_auth') as challenge_consumed,
           (select signature_counter::text from webauthn_credentials where id=$2)
             as credential_counter,
           (select state from pending_action_feed where id=$3) as pending_state,
           (select count(*)::text from feed_tombstones where removed_feed_id=$3)
             as tombstone_count,
           (select consent_record_id from onboarding_attestations
             where onboarding_browser_stage_id=$1) as consent_record_id,
           (select (convert_from(canonical_payload,'UTF8')::jsonb#>>
                     '{details,comprehensionClaimed}')::boolean
              from audit_events where event_type='onboarding_attested')
             as comprehension_claimed`,
        [stage.id, fixture.credentialId, pendingId]
      );
      expect(proof.rows[0]).toEqual({
        attestation_count: "1",
        challenge_consumed: true,
        comprehension_claimed: false,
        consent_record_id: null,
        credential_counter: "1",
        pending_state: "resolved",
        stage_state: "completed",
        tombstone_count: "1"
      });
      const consistency = await withWorkerTransaction(
        owner,
        (client) => inspectFeedConsistencyInTransaction(client, fixture.actor.organizationId),
        { assumeRole: "boardagent_worker", isolation: "repeatable read" }
      );
      // This older fixture deliberately seeds a minimal non-production pending payload.
      // Check the repaired attestation/tombstone relation; full worker validity belongs
      // to the cold workflow using production-created pending actions.
      expect(consistency).toMatchObject({ checkedTombstoneRows: 1, tombstoneBindingMismatches: 0 });
      const rollbackFixture = new Error("rollback deliberately mismatched attestation reference");
      await expect(
        withWorkerTransaction(owner, async (client) => {
          await client.query("alter table audit_events disable trigger user");
          await client.query(
            "update audit_events set object_id=$1 where event_type='onboarding_attested'",
            [testId(719999)]
          );
          await client.query("set local role boardagent_worker");
          const mismatched = await inspectFeedConsistencyInTransaction(
            client,
            fixture.actor.organizationId
          );
          expect(mismatched.tombstoneBindingMismatches).toBe(1);
          throw rollbackFixture;
        })
      ).rejects.toBe(rollbackFixture);

      const status = await components.reads.executeRead(
        fixture.principal,
        "get_onboarding_status",
        { schema_version: TOOL_INPUT_SCHEMA_VERSION, board_id: fixture.actor.boardId }
      );
      expect(record(status.data)).toEqual({
        board_id: fixture.actor.boardId,
        status: "current",
        terms_version_id: fixture.termsVersionId
      });
      await expect(components.onboarding.begin({ stageToken })).rejects.toBeInstanceOf(
        BuiltinOnboardingError
      );
    });
  });

  it("fails closed without consuming the passkey when current terms race the ceremony", async () => {
    await withDatabase(async (owner) => {
      const fixture = await seedRequiredOnboarding(owner, 72_000);
      const components = onboardingComponents(owner, 72_100);
      const prepared = await components.surface.executeDirect(
        fixture.principal,
        "prepare_onboarding_attestation",
        stageArguments(fixture, "onboarding-race-0001")
      );
      const stageToken = new URL(String(record(prepared.data)["onboarding_url"])).hash.slice(1);
      const tokenSha256 = createHash("sha256").update(stageToken, "utf8").digest("hex");
      const cachedCandidate = await components.browserStore.findCandidate({
        organizationId: fixture.actor.organizationId,
        stageTokenSha256: tokenSha256
      });
      if (!cachedCandidate) throw new Error("onboarding race candidate was not staged");
      await components.onboarding.begin({ stageToken });
      const challenge = await owner.query<{ challenge_sha256: string; id: string }>(
        `select id,encode(challenge_sha256,'hex') as challenge_sha256
           from webauthn_challenges where purpose='recent_auth' and consumed_at is null`
      );
      const challengeRow = challenge.rows[0];
      if (!challengeRow) throw new Error("recent-auth challenge was not persisted");

      await owner.query(
        `insert into onboarding_terms_versions(
           id,organization_id,seat_role,version,schema_version,canonical_text,canonical_sha256,
           material_change,effective_at,created_by
         ) values ($1,$2,'voting_member',3,'boardagent.onboarding-terms.v1',
                   'Director terms version three',$3,true,
                   transaction_timestamp()-interval '1 millisecond',$4)`,
        [testId(72_900), fixture.actor.organizationId, testHash(205), fixture.actor.memberId]
      );

      await expect(
        components.webauthnStore.completeAuthentication({
          organizationId: fixture.actor.organizationId,
          challengeId: challengeRow.id,
          expectedChallengeSha256: challengeRow.challenge_sha256,
          credentialId: fixture.credentialId,
          expectedCounter: 0,
          expectedBackupEligible: false,
          newCounter: 1,
          newBackupState: false,
          onboarding: {
            organizationId: fixture.actor.organizationId,
            boardId: fixture.actor.boardId,
            memberId: fixture.actor.memberId,
            sessionId: fixture.sessionId,
            stageId: cachedCandidate.stageId,
            stageTokenSha256: tokenSha256,
            attestationId: testId(72_901),
            auditEventId: testId(72_902),
            tombstoneId: testId(72_903)
          }
        })
      ).resolves.toBe(false);

      const unchanged = await owner.query<{
        attestation_count: string;
        challenge_consumed_at: Date | null;
        credential_counter: string;
        stage_state: string;
      }>(
        `select
           (select count(*)::text from onboarding_attestations
             where onboarding_browser_stage_id=$1) as attestation_count,
           (select state from onboarding_browser_stages where id=$1) as stage_state,
           (select consumed_at from webauthn_challenges where id=$2) as challenge_consumed_at,
           (select signature_counter::text from webauthn_credentials where id=$3)
             as credential_counter`,
        [cachedCandidate.stageId, challengeRow.id, fixture.credentialId]
      );
      expect(unchanged.rows[0]).toEqual({
        attestation_count: "0",
        challenge_consumed_at: null,
        credential_counter: "0",
        stage_state: "active"
      });
      await expect(
        components.browserStore.findCandidate({
          organizationId: fixture.actor.organizationId,
          stageTokenSha256: tokenSha256
        })
      ).resolves.toBeNull();
    });
  });
});

describe("published onboarding versions require fresh personal acceptance", () => {
  it.each(["terms", "support"] as const)(
    "publishes %s and completes the existing protected browser ceremony",
    async (kind) => {
      await withDatabase(async (owner) => {
        // Privileged fixtures create a current synthetic identity only. Publication/reattestation use supported runtime paths.
        const fixture = await seedRequiredOnboarding(owner, 97_000, false);
        await owner.query(
          "update board_memberships set is_secretary=true,entitlement_generation=entitlement_generation+1 where member_id=$1",
          [fixture.actor.memberId]
        );
        await owner.query(
          "insert into organization_role_assignments(id,organization_id,member_id,role,change_reason) values($1,$2,$3,'admin','Synthetic terms publisher fixture')",
          [testId(97_800), fixture.actor.organizationId, fixture.actor.memberId]
        );
        const scopes = [...SCOPES, "secretariat:admin"];
        await owner.query("update access_token_records set scope_set=$1 where id=$2", [
          scopes,
          fixture.actor.accessTokenRecordId
        ]);
        const principal = {
          ...fixture.principal,
          scopes,
          roles: ["admin", "member", "secretariat"]
        };
        const c = onboardingComponents(owner, 98_000);
        const original = (
          await owner.query("select to_jsonb(a) value from onboarding_attestations a order by id")
        ).rows;
        const newId = testId(97_801);
        await confirmSyntheticSurfaceAction(
          c.surface,
          principal,
          kind === "terms" ? "publish_onboarding_terms" : "publish_secretary_support",
          {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            version_id: newId,
            reason: "Publish the reviewed current onboarding information",
            idempotency_key: `onboarding-publication-${kind}-test`,
            ...(kind === "terms"
              ? {
                  seat_role: "voting_member",
                  canonical_text:
                    "Directors must examine the exact source records and personally decide."
                }
              : {
                  board_id: fixture.actor.boardId,
                  support_name: "Secretary support desk",
                  contact_methods: [{ kind: "phone", value: "+971555010000" }]
                })
          }
        );
        expect(
          (await owner.query("select to_jsonb(a) value from onboarding_attestations a order by id"))
            .rows
        ).toEqual(original);
        const status = await c.reads.executeRead(principal, "get_onboarding_status", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          board_id: fixture.actor.boardId
        });
        expect(record(status.data)["status"]).toBe("required");
        await expect(
          c.reads.executeRead(principal, "get_board", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            board_id: fixture.actor.boardId
          })
        ).rejects.toThrow(/onboarding_required/u);
        const request = {
          ...stageArguments(fixture, "published-onboarding-acceptance"),
          terms_version_id: kind === "terms" ? newId : fixture.termsVersionId,
          support_version_id: kind === "support" ? newId : fixture.actor.supportVersionId
        };
        const prepared = await c.surface.executeDirect(
          principal,
          "prepare_onboarding_attestation",
          request
        );
        const stageToken = new URL(String(record(prepared.data)["onboarding_url"])).hash.slice(1);
        const begun = await c.onboarding.begin({ stageToken });
        expect(begun.terms.versionId).toBe(request.terms_version_id);
        expect(begun.secretarySupport.versionId).toBe(request.support_version_id);
        const completed = await c.onboarding.complete({
          stageToken,
          response: authenticationResponse
        });
        expect(completed.status).toBe("current");
        expect(
          (
            await owner.query(
              "select count(*)::int n from onboarding_attestations where member_id=$1",
              [fixture.actor.memberId]
            )
          ).rows[0]
        ).toEqual({ n: 2 });
        expect(
          (
            await owner.query(
              "select to_jsonb(a) value from onboarding_attestations a where id=$1",
              [original[0].value.id]
            )
          ).rows
        ).toEqual(original.slice(0, 1));
        const current = await c.reads.executeRead(principal, "get_onboarding_status", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          board_id: fixture.actor.boardId
        });
        expect(record(current.data)["status"]).toBe("current");
        await expect(
          c.reads.executeRead(principal, "get_board", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            board_id: fixture.actor.boardId
          })
        ).resolves.toMatchObject({ status: "ok" });
      });
    }
  );
});
