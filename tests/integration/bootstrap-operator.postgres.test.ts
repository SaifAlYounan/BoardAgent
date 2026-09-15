import { createHash } from "node:crypto";
import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import { migrate, withBootstrapTransaction } from "../../lib/db/src/index.js";
import { BoardAgentBootstrapOperator } from "../../scripts/src/bootstrap.js";
import { runOperator } from "../../scripts/src/operator.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

async function withDatabase<T>(run: (pool: Pool, databaseUrl: string) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_bootstrap_operator_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 6 });
  try {
    await migrate(pool, MIGRATIONS, "bootstrap-operator-test");
    return await run(pool, testUrl.toString());
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

function setupInput() {
  return {
    organizationLegalName: "BoardAgent Test Organization Ltd",
    organizationDisplayName: "BoardAgent Test",
    organizationSlug: "boardagent-test",
    timezone: "UTC",
    canonicalResourceUri: "https://boardagent.test/mcp",
    boardSlug: "main-board",
    boardName: "Main Board",
    boardCanonicalPayload: {
      schemaVersion: "boardagent.board.v1",
      name: "Main Board",
      slug: "main-board",
      timezone: "UTC"
    },
    firstSecretaryLegalName: "Initial Secretary",
    firstSecretaryDisplayName: "Initial Secretary",
    votingWeight: 1,
    supportName: "Board secretary",
    supportContactMethods: [{ kind: "operator_reference", value: "local-bootstrap" }],
    onboardingTermsText: "Review the canonical record and secure your agent and local copies.",
    invitationHandoffMethod: "in-person QR"
  } as const;
}

describe("first-secretary bootstrap operator", () => {
  it("observes the complete pilot table inventory under the backup role and refuses incomplete visibility", async () => {
    await withDatabase(async (pool, databaseUrl) => {
      const initialized = await new BoardAgentBootstrapOperator(pool, {
        assumeRole: "boardagent_migrator"
      }).initialize(setupInput());
      if (initialized.status !== "created") throw new Error("expected fresh fixture");
      const env = {
        BOARDAGENT_ENV: "test",
        BOARDAGENT_BACKUP_DATABASE_URL: databaseUrl,
        BOARDAGENT_ORGANIZATION_ID: initialized.organizationId
      };
      const lines: string[] = [];
      expect(
        await runOperator(["inspect-pilot-state"], env, {
          stdout: (line) => lines.push(line),
          stderr: () => undefined
        })
      ).toBe(0);
      const report = JSON.parse(lines.join(""));
      expect(report).toMatchObject({
        schemaVersion: "boardagent.operator-pilot-state.v1",
        command: "inspect-pilot-state",
        status: "observed",
        readOnly: true,
        organizationId: initialized.organizationId,
        membersByState: [{ state: "invited", count: "1" }],
        tableRowCounts: {
          members: "1",
          webauthn_credentials: "0",
          onboarding_attestations: "0",
          documents: "0",
          meetings: "0",
          oauth_clients: "0"
        }
      });
      const tables = await pool.query(
        "select tablename from pg_catalog.pg_tables where schemaname='public' order by tablename"
      );
      expect(Object.keys(report.tableRowCounts).toSorted()).toEqual(
        tables.rows.map((row) => row.tablename)
      );
      // The report must not hide existing governance rows under a narrower role policy.
      await pool.query("revoke select on public.members from boardagent_backup");
      await expect(
        runOperator(["inspect-pilot-state"], env, {
          stdout: () => undefined,
          stderr: () => undefined
        })
      ).rejects.toMatchObject({ code: "42501" });
    });
  });
  it("uses an enforced read-only bootstrap inventory transaction", async () => {
    await withDatabase(async (pool) => {
      const options = { assumeRole: "boardagent_migrator" as const, readOnly: true };
      const mode = await withBootstrapTransaction(
        pool,
        async (client) =>
          (await client.query("show transaction_read_only")).rows[0]?.transaction_read_only,
        options
      );
      expect(mode).toBe("on");
      await expect(
        withBootstrapTransaction(
          pool,
          (client) => client.query("update organizations set display_name=display_name"),
          options
        )
      ).rejects.toMatchObject({ code: "25006" });
    });
  });
  it("reports missing roles on an existing one-role arrangement and replay does not fabricate the missing records", async () => {
    await withDatabase(async (pool, databaseUrl) => {
      // Historical one-role database shape; this fixture does not execute an older image.
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        isSecretary: true,
        scopes: ["governance:read"]
      });
      await pool.query(
        "insert into onboarding_terms_versions(id,organization_id,seat_role,version,schema_version,canonical_text,canonical_sha256,material_change,effective_at,created_by) values($1,$2,'management',1,'boardagent.onboarding-terms.v1','Future terms',$3,true,transaction_timestamp()+interval '1 day',$4)",
        [testId(33_991), actor.organizationId, Buffer.alloc(32, 0x72), actor.memberId]
      );
      const before = JSON.stringify(
        (
          await pool.query(
            "select (select jsonb_agg(to_jsonb(t) order by id) from onboarding_terms_versions t) as terms,(select count(*) from onboarding_attestations) as attestations,(select count(*) from audit_events) as audit"
          )
        ).rows
      );
      expect(
        await new BoardAgentBootstrapOperator(pool, {
          assumeRole: "boardagent_migrator"
        }).initialize(setupInput())
      ).toEqual({ status: "already_initialized", secretOnce: true });
      const outputs: string[] = [];
      expect(
        await runOperator(
          ["check-bootstrap"],
          {
            BOARDAGENT_ENV: "test",
            BOARDAGENT_DATABASE_URL: databaseUrl,
            BOARDAGENT_ORGANIZATION_ID: actor.organizationId
          },
          { stdout: (line) => outputs.push(line), stderr: () => undefined }
        )
      ).toBe(1);
      expect(JSON.parse(outputs.join(""))).toMatchObject({
        checks: "onboarding_terms",
        status: "incomplete",
        allSeatRolesCovered: false,
        terms: [
          { seatRole: "voting_member", availableVersions: 1, version: 1 },
          { seatRole: "management", availableVersions: 0, version: null },
          { seatRole: "observer", availableVersions: 0, version: null }
        ]
      });
      expect(
        JSON.stringify(
          (
            await pool.query(
              "select (select jsonb_agg(to_jsonb(t) order by id) from onboarding_terms_versions t) as terms,(select count(*) from onboarding_attestations) as attestations,(select count(*) from audit_events) as audit"
            )
          ).rows
        )
      ).toBe(before);
    });
  });

  it("reports the exact current term inventory without implying human enrollment or changing records", async () => {
    await withDatabase(async (pool, databaseUrl) => {
      const result = await new BoardAgentBootstrapOperator(pool, {
        assumeRole: "boardagent_migrator"
      }).initialize(setupInput());
      if (result.status !== "created") throw new Error("fixture did not initialize");
      const outputs: string[] = [];
      const env = {
        BOARDAGENT_ENV: "test",
        BOARDAGENT_DATABASE_URL: databaseUrl,
        BOARDAGENT_ORGANIZATION_ID: result.organizationId
      };
      const state = async () =>
        JSON.stringify(
          (
            await pool.query(
              "select (select count(*) from onboarding_terms_versions) as terms,(select count(*) from onboarding_attestations) as attestations,(select count(*) from audit_events) as audit,(select count(*) from webauthn_credentials) as credentials"
            )
          ).rows
        );
      const before = await state();
      expect(
        await runOperator(["check-bootstrap"], env, {
          stdout: (line) => outputs.push(line),
          stderr: () => undefined
        })
      ).toBe(0);
      expect(JSON.parse(outputs.join(""))).toMatchObject({
        command: "check-bootstrap",
        checks: "onboarding_terms",
        status: "complete",
        allSeatRolesCovered: true,
        organizationId: result.organizationId,
        instanceId: result.instanceId,
        terms: ["voting_member", "management", "observer"].map((seatRole) => ({
          seatRole,
          version: 1,
          availableVersions: 1
        }))
      });
      expect(await state()).toBe(before);
      await expect(
        runOperator(
          ["check-bootstrap"],
          { ...env, BOARDAGENT_ORGANIZATION_ID: testId(33_999) },
          { stdout: () => undefined, stderr: () => undefined }
        )
      ).rejects.toThrow("configured instance");
    });
  });

  it("reveals the invitation once and completes the exact bootstrap activation from a human code", async () => {
    await withDatabase(async (pool) => {
      let identifier = 33_001;
      const invitationBytes = Buffer.alloc(32, 0xa7);
      const operator = new BoardAgentBootstrapOperator(pool, {
        assumeRole: "boardagent_migrator",
        now: () => new Date("2026-09-02T10:00:00.000Z"),
        newId: () => testId(identifier++),
        entropy: (length) => {
          expect(length).toBe(32);
          return invitationBytes;
        }
      });

      const initialized = await operator.initialize(setupInput());
      expect(initialized.status).toBe("created");
      if (initialized.status !== "created") throw new Error("bootstrap did not initialize");
      expect(initialized.secretOnce).toBe(true);
      expect(initialized.enrollmentUrl).toBe(
        `https://boardagent.test/enroll#${invitationBytes.toString("base64url")}`
      );

      const invitationToken = new URL(initialized.enrollmentUrl).hash.slice(1);
      const stored = await pool.query<{
        token_sha256: string;
        audit_payload: string;
      }>(
        `select encode(invitation.token_sha256,'hex') as token_sha256,
                convert_from(audit.canonical_payload,'UTF8') as audit_payload
           from enrollment_invitations as invitation
           join audit_events as audit
             on audit.object_type='enrollment_invitation' and audit.object_id=invitation.id
          where invitation.id=$1`,
        [initialized.invitationId]
      );
      expect(stored.rows[0]?.token_sha256).toBe(
        createHash("sha256").update(invitationToken, "utf8").digest("hex")
      );
      expect(JSON.stringify(stored.rows)).not.toContain(invitationToken);

      const replay = await operator.initialize(setupInput());
      expect(replay).toEqual({ status: "already_initialized", secretOnce: true });
      expect(JSON.stringify(replay)).not.toContain(invitationToken);

      const activationCode = "ABC-DEFG";
      const challengeId = testId(33_090);
      await pool.query(
        "update members set state='enrollment_pending',row_version=row_version+1 where id=$1",
        [initialized.firstMemberId]
      );
      await pool.query(
        "update members set state='pending_activation',row_version=row_version+1 where id=$1",
        [initialized.firstMemberId]
      );
      await pool.query(
        `update enrollment_invitations
            set consumed_at=transaction_timestamp(),pending_activation_member_id=member_id
          where id=$1`,
        [initialized.invitationId]
      );
      await pool.query(
        `insert into webauthn_credentials(
           id,organization_id,member_id,credential_id,public_key,signature_counter,
           transports,backup_eligible,backup_state,state
         ) values ($1,$2,$3,$4,$5,0,array['internal'],false,false,'active')`,
        [
          testId(33_091),
          initialized.organizationId,
          initialized.firstMemberId,
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
          initialized.organizationId,
          initialized.firstMemberId,
          initialized.invitationId,
          createHash("sha256").update(activationCode, "utf8").digest()
        ]
      );

      const denied = await operator.activateFirstSecretary({
        activationCode: "ZZZ-ZZZZ",
        proofingMethod: "in_person"
      });
      expect(denied).toMatchObject({
        activated: false,
        reason: "code_mismatch",
        challengeState: "issued",
        attemptCount: 1
      });
      const activated = await operator.activateFirstSecretary({
        activationCode: "  abc-defg  ",
        proofingMethod: "in_person"
      });
      expect(activated).toMatchObject({
        activated: true,
        memberId: initialized.firstMemberId,
        feedCount: 1
      });

      const projection = await pool.query<{
        member_state: string;
        challenge_state: string;
        feed_count: string;
        audit_payloads: string;
      }>(
        `select member.state as member_state,challenge.state as challenge_state,
                (select count(*)::text from pending_action_feed
                  where member_id=member.id and action_type='complete_onboarding') as feed_count,
                (select string_agg(convert_from(canonical_payload,'UTF8'),' ' order by sequence)
                   from audit_events where organization_id=member.organization_id) as audit_payloads
           from members as member
           join enrollment_activation_challenges as challenge on challenge.member_id=member.id
          where member.id=$1`,
        [initialized.firstMemberId]
      );
      expect(projection.rows[0]).toMatchObject({
        member_state: "active",
        challenge_state: "consumed",
        feed_count: "1"
      });
      expect(projection.rows[0]?.audit_payloads).not.toContain(activationCode);
      expect(projection.rows[0]?.audit_payloads).not.toContain("ZZZ-ZZZZ");
      await expect(
        operator.activateFirstSecretary({
          activationCode,
          proofingMethod: "in_person"
        })
      ).rejects.toMatchObject({ code: "bootstrap_activation_unavailable" });
    });
  });
});
