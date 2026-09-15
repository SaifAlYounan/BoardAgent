import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { BoardAgentBootstrapOperator } from "../../scripts/src/bootstrap.js";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";
import { testId } from "../helpers/authorized-actor.js";

const CODE = "ABC-DEFG";
const ORIGIN = "https://activation.boardagent.test";
const ARGS = ["bootstrap", "activate-first"];

async function invoke(
  env: NodeJS.ProcessEnv,
  input: string | Buffer,
  args: readonly string[] = ARGS,
  keepInputOpen = false
) {
  const child = spawn(
    process.execPath,
    [
      path.resolve("node_modules/tsx/dist/cli.mjs"),
      "--tsconfig",
      "scripts/tsconfig.json",
      "scripts/src/operator.ts",
      ...args
    ],
    { env: { ...process.env, ...env }, stdio: ["pipe", "pipe", "pipe"] }
  );
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => (stdout += chunk));
  child.stderr.on("data", (chunk: string) => (stderr += chunk));
  child.stdin.on("error", () => {
    /* Refusal may close stdin before the writer finishes. */
  });
  const timer = setTimeout(() => child.kill("SIGKILL"), 8_000);
  try {
    if (keepInputOpen) child.stdin.write(input);
    else child.stdin.end(input);
    const result = await new Promise<{ code: number | null; signal: string | null }>(
      (resolve, reject) => {
        child.once("error", reject);
        child.once("close", (code, signal) => resolve({ code, signal }));
      }
    );
    expect(result.signal, "operator must finish without the test timeout").toBeNull();
    expect(stdout + stderr).not.toContain(CODE);
    expect(stdout + stderr).not.toContain("ZZZ-ZZZZ");
    return { ...result, stdout, stderr };
  } finally {
    clearTimeout(timer);
    child.stdin.destroy();
  }
}

describe("AC23 supported first activation CLI", () => {
  for (const proofingMethod of ["in_person", "verified_number_call"] as const) {
    it(`activates once through bounded stdin after ${proofingMethod} and leaves human onboarding pending`, async () => {
      await withAdministrativeDatabase(async (pool) => {
        const initialized = await new BoardAgentBootstrapOperator(pool, {
          assumeRole: "boardagent_migrator"
        }).initialize({
          organizationLegalName: "Activation Fixture Ltd",
          organizationDisplayName: "Activation Fixture",
          organizationSlug: "activation-fixture",
          timezone: "UTC",
          canonicalResourceUri: `${ORIGIN}/mcp`,
          boardSlug: "main",
          boardName: "Main",
          boardCanonicalPayload: { schemaVersion: "boardagent.board.v1", name: "Main" },
          firstSecretaryLegalName: "Setup Person",
          firstSecretaryDisplayName: "Setup Person",
          votingWeight: 1,
          supportName: "Local Operator",
          supportContactMethods: [{ kind: "operator_reference", value: "local-test" }],
          onboardingTermsText: "Read canonical records and secure your separate agent.",
          invitationHandoffMethod: "synthetic fixture"
        });
        if (initialized.status !== "created") throw new Error("fixture did not initialize");
        const env = {
          BOARDAGENT_ENV: "test",
          BOARDAGENT_DATABASE_URL: pool.options.connectionString,
          BOARDAGENT_PUBLIC_BASE_URL: ORIGIN
        };
        const input = JSON.stringify({ activationCode: CODE, proofingMethod });
        // This synthetic registration state tests operator transport and the existing
        // transaction. It is explicitly not a real WebAuthn/human enrollment claim.
        expect((await invoke(env, input)).code).toBe(1);
        await pool.query(
          "update members set state='enrollment_pending',row_version=row_version+1 where id=$1",
          [initialized.firstMemberId]
        );
        await pool.query(
          "update members set state='pending_activation',row_version=row_version+1 where id=$1",
          [initialized.firstMemberId]
        );
        await pool.query(
          "update enrollment_invitations set consumed_at=transaction_timestamp(),pending_activation_member_id=member_id where id=$1",
          [initialized.invitationId]
        );
        await pool.query(
          `insert into webauthn_credentials(id,organization_id,member_id,credential_id,public_key,signature_counter,transports,backup_eligible,backup_state,state)
           values($1,$2,$3,$4,$5,0,array['internal'],false,false,'active')`,
          [
            testId(99_001),
            initialized.organizationId,
            initialized.firstMemberId,
            Buffer.alloc(32, 0x31),
            Buffer.alloc(32, 0x32)
          ]
        );
        await pool.query(
          `insert into enrollment_activation_challenges(id,organization_id,member_id,invitation_id,protected_code,proofing_method,state,expires_at)
           values($1,$2,$3,$4,$5,$6,'issued',transaction_timestamp()+interval '10 minutes')`,
          [
            testId(99_002),
            initialized.organizationId,
            initialized.firstMemberId,
            initialized.invitationId,
            createHash("sha256").update(CODE).digest(),
            proofingMethod
          ]
        );

        if (proofingMethod === "in_person") {
          for (const bad of [
            "",
            "null",
            "[]",
            "{}",
            "{",
            input + "{}",
            " ".repeat(1025),
            JSON.stringify({ activationCode: CODE }),
            JSON.stringify({ activationCode: CODE, proofingMethod: "email" }),
            JSON.stringify({
              activationCode: CODE,
              proofingMethod,
              memberId: initialized.firstMemberId
            }),
            `{"activationCode":"ZZZ-ZZZZ","activationCode":"${CODE}","proofingMethod":"in_person"}`,
            Buffer.concat([Buffer.from(input), Buffer.from([0xff])])
          ])
            expect((await invoke(env, bad)).code).toBe(1);
          expect((await invoke(env, "x".repeat(1025), ARGS, true)).code).toBe(1);
          for (const origin of [
            "http://activation.boardagent.test",
            "https://wrong.boardagent.test",
            `${ORIGIN}/other`,
            `${ORIGIN}?x=1`,
            `${ORIGIN}#x`,
            "https://user:password@activation.boardagent.test",
            ""
          ]) {
            expect((await invoke({ ...env, BOARDAGENT_PUBLIC_BASE_URL: origin }, input)).code).toBe(
              1
            );
          }
          expect((await invoke(env, input, [...ARGS, CODE])).code).not.toBe(0);
          expect((await invoke(env, input, ["activate-first"])).code).not.toBe(0);
          expect(
            (await pool.query("select state,attempt_count from enrollment_activation_challenges"))
              .rows
          ).toEqual([{ state: "issued", attempt_count: 0 }]);
          expect((await pool.query("select count(*)::int as n from audit_events")).rows[0]?.n).toBe(
            1
          );
        }

        const denied = await invoke(
          env,
          JSON.stringify({ activationCode: "ZZZ-ZZZZ", proofingMethod })
        );
        expect(denied.code).toBe(1);
        expect(JSON.parse(denied.stdout)).toMatchObject({
          command: "bootstrap",
          mode: "activate-first",
          status: "refused",
          activated: false,
          reason: "code_mismatch",
          attemptCount: 1
        });
        // A new process can resume an interrupted ceremony. Input is accepted at the
        // exact byte boundary; excess is rejected before any database effect above.
        const success = await invoke(env, input.padEnd(1024, " "));
        expect(success.code, success.stderr).toBe(0);
        expect(JSON.parse(success.stdout)).toMatchObject({
          schemaVersion: 1,
          command: "bootstrap",
          mode: "activate-first",
          status: "succeeded",
          activated: true,
          memberId: initialized.firstMemberId,
          nextHumanStep: "complete_onboarding"
        });
        const retained = await pool.query("select state from members where id=$1", [
          initialized.firstMemberId
        ]);
        expect(retained.rows).toEqual([{ state: "active" }]);
        expect(
          (await pool.query("select state,attempt_count from enrollment_activation_challenges"))
            .rows
        ).toEqual([{ state: "consumed", attempt_count: 1 }]);
        expect(
          (await pool.query("select count(*)::int as n from onboarding_attestations")).rows[0]?.n
        ).toBe(0);
        expect(
          (
            await pool.query(
              "select count(*)::int as n from pending_action_feed where action_type='complete_onboarding'"
            )
          ).rows[0]?.n
        ).toBe(1);
        const auditBeforeReplay = (
          await pool.query(
            "select convert_from(canonical_payload,'UTF8') as payload from audit_events order by sequence"
          )
        ).rows;
        expect(JSON.stringify(auditBeforeReplay)).not.toContain(CODE);
        expect(JSON.stringify(auditBeforeReplay)).not.toContain("ZZZ-ZZZZ");
        expect((await invoke(env, input)).code).toBe(1);
        expect(
          (
            await pool.query(
              "select convert_from(canonical_payload,'UTF8') as payload from audit_events order by sequence"
            )
          ).rows
        ).toEqual(auditBeforeReplay);
      });
    }, 90_000);
  }
});
