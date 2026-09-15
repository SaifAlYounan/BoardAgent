import { createHash, generateKeyPairSync } from "node:crypto";
import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import {
  BuiltinOnboardingService,
  PgBoardAgentSurfaceService,
  PgOnboardingBrowserStore,
  PgWebAuthnStore,
  WebAuthnCeremony,
  type SurfacePrincipal
} from "../../artifacts/server/src/index.js";
import { DirectReadRepository } from "../helpers/direct-response-allocation.js";
import {
  CREDENTIAL_ID,
  allowAllWebAuthnAttempts,
  authenticationResponse,
  fakeWebAuthnCrypto,
  idSequence
} from "../browser/webauthn-harness.js";

import {
  activateBootstrapEnrollmentInTransaction,
  bootstrapInstanceInTransaction,
  migrate,
  withBootstrapTransaction,
  withIdentityTransaction,
  type BootstrapInstanceInput
} from "../../lib/db/src/index.js";
import { testId } from "../helpers/authorized-actor.js";
import { bootstrapOAuthFixture, testAuthenticator } from "../helpers/administrative-oauth.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_bootstrap_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 6 });
  try {
    await migrate(pool, MIGRATIONS, "bootstrap-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

function bootstrapInput(): BootstrapInstanceInput {
  return {
    organizationId: testId(32_001),
    organizationLegalName: "BoardAgent Test Organization",
    organizationDisplayName: "BoardAgent Test",
    organizationSlug: "boardagent-test",
    timezone: "UTC",
    instanceId: testId(32_002),
    canonicalResourceUri: "https://boardagent.test/mcp",
    boardId: testId(32_003),
    boardVersionId: testId(32_004),
    boardSlug: "main-board",
    boardName: "Main Board",
    boardCanonicalPayload: {
      schemaVersion: "boardagent.board.v1",
      name: "Main Board",
      slug: "main-board",
      timezone: "UTC"
    },
    memberId: testId(32_005),
    memberLegalName: "Initial Secretary",
    memberDisplayName: "Initial Secretary",
    adminRoleAssignmentId: testId(32_006),
    secretariatRoleAssignmentId: testId(32_007),
    membershipId: testId(32_008),
    membershipVersionId: testId(32_009),
    votingWeight: 1,
    supportVersionId: testId(32_010),
    supportName: "Board secretary",
    supportContactMethods: [{ kind: "operator_reference", value: "local-bootstrap" }],
    onboardingTermsVersionId: testId(32_011),
    onboardingTermsText: "Review the canonical record and secure your agent and local copies.",
    invitationId: testId(32_012),
    invitationTokenSha256: "11".repeat(32),
    invitationHandoffMethod: "in-person QR",
    auditEventId: testId(32_013)
  };
}

describe("one-use instance bootstrap transaction", () => {
  it.each(["current", "expired", "exhausted"] as const)(
    "MR-BOOT-001 diagnoses the first registered person's %s activation with retained identity evidence",
    async (challengeState) => {
      await withDatabase(async (pool) => {
        const fixture = await bootstrapOAuthFixture(pool);
        try {
          const first = fixture.initialized;
          const person = fixture.browserSession();
          const authenticator = testAuthenticator();
          const page = await person.get("/enroll");
          expect(page.status).toBe(200);
          const csrf = /name="csrf_token" value="([A-Za-z0-9_.-]+)"/u.exec(await page.text())?.[1];
          if (!csrf) throw new Error("first enrollment page has no CSRF token");
          const common = {
            csrf_token: csrf,
            invitation_token: new URL(first.enrollmentUrl).hash.slice(1)
          };
          const begun = await person.post("/enroll/passkey/begin", common);
          expect(begun.status).toBe(200);
          const options = (await begun.json()) as { publicKey: { challenge: string } };
          const registered = await person.post("/enroll/passkey/complete", {
            ...common,
            proofing_method: "in_person",
            credential: JSON.stringify(
              authenticator.registration(options.publicKey.challenge, fixture.origin)
            )
          });
          expect(registered.status).toBe(200);
          const handoff = (await registered.json()) as {
            status: string;
            activationCode: string;
            activationChallengeId: string;
            memberId: string;
            invitationId: string;
          };
          expect(handoff).toMatchObject({
            status: "pending_activation",
            memberId: first.firstMemberId,
            invitationId: first.invitationId
          });
          expect(handoff.activationCode).toMatch(/^[A-HJ-NP-Z2-9]{3}-[A-HJ-NP-Z2-9]{4}$/u);
          const identityBefore = (
            await pool.query(
              "select id,credential_id,public_key,state from webauthn_credentials order by id"
            )
          ).rows;
          expect(identityBefore).toHaveLength(1);
          expect(identityBefore[0]?.credential_id).toEqual(authenticator.id);
          const registrationAudit = (
            await pool.query("select * from audit_events order by sequence")
          ).rows;
          const activate = () =>
            fixture.operator.activateFirstSecretary({
              activationCode: handoff.activationCode,
              proofingMethod: "in_person"
            });

          if (challengeState === "current") {
            expect(await activate()).toMatchObject({
              activated: true,
              memberId: first.firstMemberId,
              feedCount: 1
            });
            expect((await pool.query("select state from members")).rows).toEqual([
              { state: "active" }
            ]);
          } else {
            if (challengeState === "expired") {
              // Simulate elapsed challenge time only, in this disposable database.
              // Registration, identity, invitation, credentials and guards remain intact.
              await pool.query(
                "update enrollment_activation_challenges set expires_at=transaction_timestamp()-interval '1 second' where id=$1",
                [handoff.activationChallengeId]
              );
            } else {
              const wrongCode = handoff.activationCode === "ZZZ-ZZZZ" ? "YYY-YYYY" : "ZZZ-ZZZZ";
              for (let attempt = 1; attempt <= 20; attempt += 1) {
                expect(
                  await fixture.operator.activateFirstSecretary({
                    activationCode: wrongCode,
                    proofingMethod: "in_person"
                  })
                ).toMatchObject({
                  activated: false,
                  reason: "code_mismatch",
                  attemptCount: attempt,
                  challengeState: attempt === 20 ? "revoked" : "issued"
                });
              }
            }
            const retained = async () =>
              (
                await pool.query(`select
                  (select jsonb_agg(to_jsonb(value) order by id) from members value) as members,
                  (select jsonb_agg(to_jsonb(value) order by id) from board_memberships value) as seats,
                  (select jsonb_agg(to_jsonb(value) order by id) from organization_role_assignments value) as roles,
                  (select jsonb_agg(to_jsonb(value) order by id) from enrollment_invitations value) as invitations,
                  (select jsonb_agg(to_jsonb(value) order by id) from webauthn_credentials value) as credentials,
                  (select jsonb_agg(to_jsonb(value) order by id) from enrollment_activation_challenges value) as challenges,
                  (select jsonb_agg(to_jsonb(value) order by sequence) from audit_events value) as audit,
                  (select jsonb_agg(to_jsonb(value) order by id) from pending_action_feed value) as feed`)
              ).rows;
            const beforeRefusals = await retained();
            await expect(activate()).rejects.toMatchObject({
              code: "bootstrap_activation_unavailable"
            });
            await expect(
              fixture.operator.renewFirstInvitation({
                instanceId: first.instanceId,
                organizationId: first.organizationId,
                memberId: first.firstMemberId,
                previousInvitationId: first.invitationId,
                canonicalResourceUri: `${fixture.origin}/mcp`,
                handoffMethod: "in-person replacement QR",
                reason: "The first person's registered activation is no longer usable"
              })
            ).rejects.toMatchObject({ code: "bootstrap_renewal_unavailable" });
            expect(await retained()).toEqual(beforeRefusals);
            expect((await pool.query("select state from members")).rows).toEqual([
              { state: "pending_activation" }
            ]);
            expect(
              (await pool.query("select count(*)::int as count from pending_action_feed")).rows
            ).toEqual([{ count: 0 }]);
          }
          expect(
            (
              await pool.query(
                "select id,credential_id,public_key,state from webauthn_credentials order by id"
              )
            ).rows
          ).toEqual(identityBefore);
          expect(
            (await pool.query("select * from audit_events order by sequence")).rows.slice(
              0,
              registrationAudit.length
            )
          ).toEqual(registrationAudit);
          expect(
            (await pool.query("select count(*)::int as count from onboarding_attestations")).rows
          ).toEqual([{ count: 0 }]);
        } finally {
          await fixture.close();
        }
      });
    },
    90_000
  );

  it.each(["voting_member", "management", "observer"] as const)(
    "a %s can retrieve and attest the actual bootstrapped terms before ordinary OAuth scopes become ready",
    async (seatRole) => {
      await withDatabase(async (pool) => {
        const input = bootstrapInput();
        await withBootstrapTransaction(
          pool,
          (client) => bootstrapInstanceInTransaction(client, input),
          { assumeRole: "boardagent_migrator" }
        );
        // Arrange only the already-enrolled identity and its onboarding-only client.
        // Terms/support come exclusively from real bootstrap; no attestation is seeded.
        const memberId = testId(32_050),
          clientId = testId(32_051),
          keyId = testId(32_052);
        const tokenId = testId(32_053),
          tokenJti = testId(32_054),
          sessionId = testId(32_055);
        const credentialId = testId(32_056);
        await pool.query(
          "insert into members(id,organization_id,member_kind,legal_name,display_name,state) values($1,$2,'human','Role trial','Role trial','active')",
          [memberId, input.organizationId]
        );
        await pool.query(
          "insert into board_memberships(id,organization_id,board_id,member_id,seat_role,is_secretary,voting_weight,state) values($1,$2,$3,$4,$5,false,$6,'active')",
          [
            testId(32_057),
            input.organizationId,
            input.boardId,
            memberId,
            seatRole,
            seatRole === "voting_member" ? 1 : 0
          ]
        );
        await pool.query(
          "insert into oauth_clients(id,organization_id,protocol_id_kind,protocol_id_value,safe_metadata,metadata_sha256,state,registered_by) values($1,$2,'preregistered','bootstrap-role-client','{}',$3,'active',$4)",
          [clientId, input.organizationId, Buffer.alloc(32, 41), memberId]
        );
        await pool.query(
          "insert into crypto_key_registry(id,organization_id,kid,purpose,algorithm,public_jwk,nonsecret_locator,activated_at) values($1,$2,'bootstrap-role-key','oauth_signing','ES256',$3,'synthetic-test-key',transaction_timestamp())",
          [
            keyId,
            input.organizationId,
            generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({ format: "jwk" })
          ]
        );
        await pool.query(
          "insert into auth_sessions(id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,expires_at,last_authenticated_at) values($1,$2,$3,$4,$5,'authenticated','https://boardagent.test',transaction_timestamp()+interval '1 hour',transaction_timestamp())",
          [sessionId, input.organizationId, Buffer.alloc(32, 42), memberId, clientId]
        );
        await pool.query(
          "insert into access_token_records(id,organization_id,jti,member_id,client_id,resource_uri,scope_set,session_id,signing_key_id,expires_at) values($1,$2,$3,$4,$5,'https://boardagent.test/mcp',array['onboarding:read'],$6,$7,transaction_timestamp()+interval '10 minutes')",
          [tokenId, input.organizationId, tokenJti, memberId, clientId, sessionId, keyId]
        );
        await pool.query(
          "insert into webauthn_credentials(id,organization_id,member_id,credential_id,public_key,signature_counter,transports,backup_eligible,backup_state,state) values($1,$2,$3,$4,$5,0,array['internal'],false,false,'active')",
          [
            credentialId,
            input.organizationId,
            memberId,
            Buffer.from(CREDENTIAL_ID, "base64url"),
            Buffer.alloc(64, 7)
          ]
        );
        const principal: SurfacePrincipal = {
          organizationId: input.organizationId,
          memberId,
          clientId,
          tokenJti,
          accessTokenRecordId: tokenId,
          protocolClientId: "bootstrap-role-client",
          serviceOrigin: "https://boardagent.test",
          keyId: "bootstrap-role-key",
          scopes: ["onboarding:read"],
          boardIds: [input.boardId],
          roles: [seatRole === "voting_member" ? "member" : seatRole]
        };
        const scopeReady = () =>
          withIdentityTransaction(
            pool,
            { organizationId: input.organizationId, boardIds: [input.boardId] },
            async (client) =>
              (
                await client.query<{ ready: boolean }>(
                  "select boardagent_identity_member_onboarding_current($1,$2,array['governance:read']) as ready",
                  [input.organizationId, memberId]
                )
              ).rows[0]?.ready,
            { assumeRole: "boardagent_server" }
          );
        expect(await scopeReady()).toBe(false);
        const reads = new DirectReadRepository(pool, {
          cursorKey: Buffer.alloc(32, 43),
          transaction: { assumeRole: "boardagent_server" }
        });
        const view = await reads.executeRead(principal, "get_onboarding", {
          schema_version: "boardagent.tool-input.v1",
          board_id: input.boardId
        });
        expect(view.data).toMatchObject({
          onboarding: {
            seat_role: seatRole,
            attested: false,
            terms: { canonical_text: input.onboardingTermsText, version: 1 }
          }
        });
        const term = (
          await pool.query<{ id: string }>(
            "select id from onboarding_terms_versions where organization_id=$1 and seat_role=$2",
            [input.organizationId, seatRole]
          )
        ).rows[0]!;
        const surface = new PgBoardAgentSurfaceService(pool, {
          reads,
          transaction: { assumeRole: "boardagent_server" },
          newId: idSequence(32_100)
        });
        const staged = await surface.executeDirect(principal, "prepare_onboarding_attestation", {
          schema_version: "boardagent.tool-input.v1",
          board_id: input.boardId,
          terms_version_id: term.id,
          support_version_id: input.supportVersionId,
          presentation_choice: "source-linked summaries",
          local_memory_choice: "no local cache",
          idempotency_key: "bootstrap-role-onboarding-0001"
        });
        const stageData = staged.data as { onboarding_url: string };
        const stageToken = new URL(stageData.onboarding_url).hash.slice(1);
        const ceremony = new WebAuthnCeremony({
          rpName: "BoardAgent",
          rpId: "boardagent.test",
          origin: "https://boardagent.test",
          store: new PgWebAuthnStore(pool, { assumeRole: "boardagent_server" }),
          attemptLimiter: allowAllWebAuthnAttempts,
          crypto: fakeWebAuthnCrypto().crypto,
          newId: idSequence(32_200)
        });
        const onboarding = new BuiltinOnboardingService({
          organizationId: input.organizationId,
          store: new PgOnboardingBrowserStore(pool, { assumeRole: "boardagent_server" }),
          webauthn: ceremony,
          newId: idSequence(32_300)
        });
        expect(await onboarding.begin({ stageToken })).toMatchObject({ seatRole });
        expect(
          await onboarding.complete({ stageToken, response: authenticationResponse })
        ).toMatchObject({
          status: "current",
          memberId,
          boardId: input.boardId,
          termsVersionId: term.id
        });
        expect(await scopeReady()).toBe(true);
        expect(
          (
            await reads.executeRead(principal, "get_onboarding_status", {
              schema_version: "boardagent.tool-input.v1",
              board_id: input.boardId
            })
          ).data
        ).toMatchObject({ status: "current", terms_version_id: term.id });
      });
    }
  );

  it("publishes the reviewed initial terms for every supported seat role without attesting for anyone", async () => {
    await withDatabase(async (pool) => {
      const input = bootstrapInput();
      await withBootstrapTransaction(
        pool,
        (client) => bootstrapInstanceInTransaction(client, input),
        { assumeRole: "boardagent_migrator" }
      );
      const terms = await pool.query<{
        id: string;
        seat_role: string;
        canonical_text: string;
        canonical_sha256: string;
        version: number;
      }>(
        "select id,seat_role,canonical_text,encode(canonical_sha256,'hex') as canonical_sha256,version from onboarding_terms_versions where organization_id=$1 order by seat_role",
        [input.organizationId]
      );
      expect(terms.rows.map(({ seat_role }) => seat_role)).toEqual([
        "management",
        "observer",
        "voting_member"
      ]);
      expect(new Set(terms.rows.map(({ id }) => id)).size).toBe(3);
      expect(terms.rows.find(({ seat_role }) => seat_role === "voting_member")?.id).toBe(
        input.onboardingTermsVersionId
      );
      for (const term of terms.rows) {
        expect(term).toMatchObject({
          canonical_text: input.onboardingTermsText,
          canonical_sha256: createHash("sha256").update(input.onboardingTermsText).digest("hex"),
          version: 1
        });
      }
      expect(
        (await pool.query("select count(*)::int as count from onboarding_attestations")).rows
      ).toEqual([{ count: 0 }]);
      await withBootstrapTransaction(
        pool,
        (client) => bootstrapInstanceInTransaction(client, input),
        { assumeRole: "boardagent_migrator" }
      );
      expect(
        (await pool.query("select count(*)::int as count from onboarding_terms_versions")).rows
      ).toEqual([{ count: 3 }]);
    });
  });

  it("creates the first board-capable admin-secretary and invitation exactly once", async () => {
    await withDatabase(async (pool) => {
      const input = bootstrapInput();
      const first = await withBootstrapTransaction(
        pool,
        (client) => bootstrapInstanceInTransaction(client, input),
        { assumeRole: "boardagent_migrator" }
      );
      expect(first).toMatchObject({
        alreadyBootstrapped: false,
        instanceId: input.instanceId,
        organizationId: input.organizationId,
        boardId: input.boardId,
        firstMemberId: input.memberId,
        invitationId: input.invitationId,
        auditEventId: input.auditEventId,
        auditSequence: "1"
      });
      const replay = await withBootstrapTransaction(
        pool,
        (client) => bootstrapInstanceInTransaction(client, input),
        { assumeRole: "boardagent_migrator" }
      );
      expect(replay).toEqual({
        alreadyBootstrapped: true,
        instanceId: input.instanceId,
        organizationId: input.organizationId,
        boardId: input.boardId,
        firstMemberId: input.memberId,
        invitationId: input.invitationId
      });
      await expect(
        withBootstrapTransaction(
          pool,
          (client) =>
            bootstrapInstanceInTransaction(client, {
              ...input,
              invitationId: testId(32_099)
            }),
          { assumeRole: "boardagent_migrator" }
        )
      ).rejects.toThrow(/different identifiers/u);

      const rows = await pool.query<{
        member_state: string;
        is_secretary: boolean;
        roles: string[];
        audit_type: string;
      }>(
        `select member.state as member_state,membership.is_secretary,
                array_agg(distinct role.role order by role.role) as roles,
                audit.event_type as audit_type
           from members as member
           join board_memberships as membership on membership.member_id=member.id
           join organization_role_assignments as role on role.member_id=member.id
           join audit_events as audit on audit.id=$1
          group by member.state,membership.is_secretary,audit.event_type`,
        [input.auditEventId]
      );
      expect(rows.rows).toEqual([
        {
          member_state: "invited",
          is_secretary: true,
          roles: ["admin", "secretariat"],
          audit_type: "enrollment_issued"
        }
      ]);
      await expect(
        withIdentityTransaction(
          pool,
          { organizationId: input.organizationId, boardIds: [input.boardId] },
          (client) =>
            client.query(
              "insert into organizations(id,legal_name,display_name,slug,timezone) values ($1,'X','X','x','UTC')",
              [testId(32_100)]
            ),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow(/permission denied/u);
    });
  });

  it("limits preidentity activation to the exact first secretary enrollment", async () => {
    await withDatabase(async (pool) => {
      const input = bootstrapInput();
      await withBootstrapTransaction(
        pool,
        (client) => bootstrapInstanceInTransaction(client, input),
        { assumeRole: "boardagent_migrator" }
      );
      const challengeId = testId(32_020);
      const credentialId = testId(32_021);
      const activationCode = "BOOT-7QZ";
      await pool.query(
        "update members set state='enrollment_pending',row_version=row_version+1 where id=$1",
        [input.memberId]
      );
      await pool.query(
        "update members set state='pending_activation',row_version=row_version+1 where id=$1",
        [input.memberId]
      );
      await pool.query(
        `update enrollment_invitations
            set consumed_at=transaction_timestamp(),pending_activation_member_id=member_id
          where id=$1`,
        [input.invitationId]
      );
      await pool.query(
        `insert into webauthn_credentials(
           id,organization_id,member_id,credential_id,public_key,signature_counter,
           transports,backup_eligible,backup_state,state
         ) values ($1,$2,$3,$4,$5,0,array['internal'],false,false,'active')`,
        [
          credentialId,
          input.organizationId,
          input.memberId,
          Buffer.alloc(32, 0x31),
          Buffer.alloc(32, 0x32)
        ]
      );
      await pool.query(
        `insert into enrollment_activation_challenges(
           id,organization_id,member_id,invitation_id,protected_code,proofing_method,state,
           expires_at
         ) values ($1,$2,$3,$4,$5,'in_person','issued',
           transaction_timestamp()+interval '10 minutes')`,
        [
          challengeId,
          input.organizationId,
          input.memberId,
          input.invitationId,
          createHash("sha256").update(activationCode, "utf8").digest()
        ]
      );

      const wrong = await withBootstrapTransaction(
        pool,
        (client) =>
          activateBootstrapEnrollmentInTransaction(client, {
            organizationId: input.organizationId,
            memberId: input.memberId,
            invitationId: input.invitationId,
            challengeId,
            protectedCodeSha256: "ff".repeat(32),
            proofingMethod: "in_person",
            feedEntries: [{ boardId: input.boardId, feedId: testId(32_022) }],
            auditEventId: testId(32_023)
          }),
        { assumeRole: "boardagent_migrator" }
      );
      expect(wrong).toMatchObject({
        activated: false,
        reason: "code_mismatch",
        challengeState: "issued",
        attemptCount: 1
      });
      await expect(
        withIdentityTransaction(
          pool,
          { organizationId: input.organizationId, boardIds: [input.boardId] },
          (client) =>
            activateBootstrapEnrollmentInTransaction(client, {
              organizationId: input.organizationId,
              memberId: input.memberId,
              invitationId: input.invitationId,
              challengeId,
              protectedCodeSha256: createHash("sha256")
                .update(activationCode, "utf8")
                .digest("hex"),
              proofingMethod: "in_person",
              feedEntries: [{ boardId: input.boardId, feedId: testId(32_024) }],
              auditEventId: testId(32_025)
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "bootstrap_context_invalid" });

      const activated = await withBootstrapTransaction(
        pool,
        (client) =>
          activateBootstrapEnrollmentInTransaction(client, {
            organizationId: input.organizationId,
            memberId: input.memberId,
            invitationId: input.invitationId,
            challengeId,
            protectedCodeSha256: createHash("sha256").update(activationCode, "utf8").digest("hex"),
            proofingMethod: "in_person",
            feedEntries: [{ boardId: input.boardId, feedId: testId(32_024) }],
            auditEventId: testId(32_025)
          }),
        { assumeRole: "boardagent_migrator" }
      );
      expect(activated).toMatchObject({
        activated: true,
        memberId: input.memberId,
        feedCount: 1
      });
      const projection = await pool.query<{
        member_state: string;
        challenge_state: string;
        feed_count: string;
        activation_events: string;
      }>(
        `select member.state as member_state,challenge.state as challenge_state,
                (select count(*)::text from pending_action_feed
                  where member_id=member.id and action_type='complete_onboarding') as feed_count,
                (select count(*)::text from audit_events
                  where object_id=member.id and event_type='member_activated') as activation_events
           from members as member
           join enrollment_activation_challenges as challenge on challenge.member_id=member.id
          where member.id=$1`,
        [input.memberId]
      );
      expect(projection.rows[0]).toEqual({
        member_state: "active",
        challenge_state: "consumed",
        feed_count: "1",
        activation_events: "1"
      });
      await expect(
        withBootstrapTransaction(
          pool,
          (client) =>
            activateBootstrapEnrollmentInTransaction(client, {
              organizationId: input.organizationId,
              memberId: input.memberId,
              invitationId: input.invitationId,
              challengeId,
              protectedCodeSha256: createHash("sha256")
                .update(activationCode, "utf8")
                .digest("hex"),
              proofingMethod: "in_person",
              feedEntries: [{ boardId: input.boardId, feedId: testId(32_026) }],
              auditEventId: testId(32_027)
            }),
          { assumeRole: "boardagent_migrator" }
        )
      ).rejects.toMatchObject({ code: "bootstrap_activation_unavailable" });
    });
  });
});
