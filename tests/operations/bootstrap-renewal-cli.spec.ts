import { mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { runOperatorWithDiagnostics } from "../../scripts/src/operator.js";
import { BoardAgentBootstrapOperator } from "../../scripts/src/bootstrap.js";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";

const origin = "https://renewal-cli.boardagent.test";

describe("SR002/SR005/SR102 first invitation renewal CLI", () => {
  it("accepts one strict request file, returns a secret once, and leaves personal activation pending", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const first = await new BoardAgentBootstrapOperator(pool, {
        assumeRole: "boardagent_migrator"
      }).initialize({
        organizationLegalName: "Synthetic Renewal CLI Ltd",
        organizationDisplayName: "Renewal CLI",
        organizationSlug: "renewal-cli",
        timezone: "UTC",
        canonicalResourceUri: `${origin}/mcp`,
        boardSlug: "main",
        boardName: "Main Board",
        boardCanonicalPayload: { schemaVersion: "boardagent.board.v1", name: "Main Board" },
        firstSecretaryLegalName: "First Administrator",
        firstSecretaryDisplayName: "First Administrator",
        votingWeight: 1,
        supportName: "Secretary office",
        supportContactMethods: [{ kind: "operator_reference", value: "synthetic-local-operator" }],
        onboardingTermsText: "Review current records and confirm personally.",
        invitationHandoffMethod: "in-person QR"
      });
      if (first.status !== "created") throw new Error("new fixture expected");
      await pool.query(
        "update enrollment_invitations set issued_at=issued_at-interval '2 days',expires_at=expires_at-interval '2 days' where id=$1",
        [first.invitationId]
      );
      const request = {
        instanceId: first.instanceId,
        organizationId: first.organizationId,
        memberId: first.firstMemberId,
        previousInvitationId: first.invitationId,
        canonicalResourceUri: `${origin}/mcp`,
        handoffMethod: "in-person replacement QR",
        reason: "The untouched first invitation expired"
      };
      const directory = await mkdtemp(path.join(tmpdir(), "boardagent-renewal-cli-"));
      const file = path.join(directory, "request.json");
      const args = ["bootstrap", "renew-first-invitation", file];
      const env = {
        BOARDAGENT_ENV: "test",
        BOARDAGENT_DATABASE_URL: pool.options.connectionString,
        BOARDAGENT_PUBLIC_BASE_URL: origin
      };
      async function invoke(command = args, environment = env) {
        const stdout: string[] = [],
          stderr: string[] = [];
        const code = await runOperatorWithDiagnostics(command, environment, {
          stdout: (line) => {
            stdout.push(line);
          },
          stderr: (line) => {
            stderr.push(line);
          }
        });
        return { code, stdout: stdout.join(""), stderr: stderr.join("") };
      }
      try {
        await writeFile(file, JSON.stringify(request), { mode: 0o600 });
        const original = await readFile(file);
        const bad = [
          "null",
          "[]",
          "{}",
          "{",
          " ".repeat(16385),
          JSON.stringify({ ...request, activate: true }),
          JSON.stringify(request).replace('"reason":', '"reason":"duplicate","reason":'),
          Buffer.concat([original, Buffer.from([255])])
        ];
        for (const contents of bad) {
          await writeFile(file, contents);
          const denied = await invoke();
          expect(denied.code).toBe(1);
          expect(denied.stdout).not.toContain("enrollmentUrl");
        }
        await writeFile(file, original);
        const link = path.join(directory, "link.json");
        await symlink(file, link);
        for (const command of [
          args.slice(0, 2),
          [...args, "extra"],
          [...args.slice(0, 2), link],
          [...args.slice(0, 2), directory]
        ])
          expect((await invoke(command)).code).not.toBe(0);
        expect(
          (
            await invoke(args, {
              ...env,
              BOARDAGENT_PUBLIC_BASE_URL: "https://other.boardagent.test"
            })
          ).code
        ).toBe(1);
        expect(
          (await pool.query("select count(*)::int as n from enrollment_invitations")).rows
        ).toEqual([{ n: 1 }]);
        expect((await pool.query("select count(*)::int as n from audit_events")).rows).toEqual([
          { n: 1 }
        ]);
        const result = await invoke();
        expect(result.code, result.stderr).toBe(0);
        expect(result.stderr).toBe("");
        expect(result.stdout.trim().split("\n")).toHaveLength(1);
        const receipt = JSON.parse(result.stdout);
        expect(receipt).toMatchObject({
          schemaVersion: 1,
          command: "bootstrap",
          mode: "renew-first-invitation",
          status: "renewed",
          secretOnce: true,
          firstMemberId: first.firstMemberId
        });
        const secret = new URL(receipt.enrollmentUrl).hash.slice(1);
        expect(secret).toHaveLength(43);
        expect(new URL(receipt.enrollmentUrl).origin).toBe(origin);
        const replay = await invoke();
        expect(replay.code).toBe(1);
        expect(replay.stdout + replay.stderr).not.toContain(secret);
        expect(await readFile(file)).toEqual(original);
        expect((await pool.query("select state from members")).rows).toEqual([
          { state: "invited" }
        ]);
        expect(
          (await pool.query("select count(*)::int as n from webauthn_credentials")).rows
        ).toEqual([{ n: 0 }]);
        expect(
          (await pool.query("select count(*)::int as n from onboarding_attestations")).rows
        ).toEqual([{ n: 0 }]);
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    });
  });
});
