import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { runOperatorWithDiagnostics } from "../../scripts/src/operator.js";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";
import { bootstrapOAuthFixture, testAuthenticator } from "../helpers/administrative-oauth.js";

function csrfOf(html: string): string {
  const token = /name="csrf_token" value="([A-Za-z0-9_.-]+)"/u.exec(html)?.[1];
  if (!token) throw new Error("ceremony page has no CSRF token");
  return token;
}

describe("SR-102 first activation restart CLI", () => {
  it("restarts the registered first administrator's lapsed activation once, through the browser, then activates with the fresh code", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await bootstrapOAuthFixture(pool);
      const directory = await mkdtemp(path.join(tmpdir(), "boardagent-restart-cli-"));
      try {
        const first = f.initialized;
        // The first administrator registers a passkey, then the ten-minute code lapses.
        const person = f.browserSession();
        const page = await person.get("/enroll");
        const common = {
          csrf_token: csrfOf(await page.text()),
          invitation_token: new URL(first.enrollmentUrl).hash.slice(1)
        };
        const begun = await person.post("/enroll/passkey/begin", common);
        expect(begun.status).toBe(200);
        const options = (await begun.json()) as { publicKey: { challenge: string } };
        const auth = testAuthenticator();
        const completed = await person.post("/enroll/passkey/complete", {
          ...common,
          proofing_method: "in_person",
          credential: JSON.stringify(auth.registration(options.publicKey.challenge, f.origin))
        });
        expect(completed.status).toBe(200);
        const pending = (await completed.json()) as {
          activationChallengeId: string;
          activationCode: string;
        };
        await pool.query(
          "update enrollment_activation_challenges set expires_at=transaction_timestamp()-interval '1 minute' where id=$1",
          [pending.activationChallengeId]
        );
        await expect(
          f.operator.activateFirstSecretary({
            activationCode: pending.activationCode,
            proofingMethod: "in_person"
          })
        ).rejects.toThrow();

        const request = {
          instanceId: first.instanceId,
          organizationId: first.organizationId,
          memberId: first.firstMemberId,
          canonicalResourceUri: `${f.origin}/mcp`,
          proofingMethod: "in_person",
          reason: "The first activation code expired before the operator confirmed it"
        };
        const file = path.join(directory, "restart.json");
        await writeFile(file, JSON.stringify(request), { mode: 0o600 });
        const env = {
          BOARDAGENT_ENV: "test",
          BOARDAGENT_DATABASE_URL: pool.options.connectionString,
          BOARDAGENT_PUBLIC_BASE_URL: f.origin
        };
        const invoke = async (args: string[]) => {
          const stdout: string[] = [];
          const stderr: string[] = [];
          const code = await runOperatorWithDiagnostics(args, env, {
            stdout: (line) => {
              stdout.push(line);
            },
            stderr: (line) => {
              stderr.push(line);
            }
          });
          return { code, stdout: stdout.join(""), stderr: stderr.join("") };
        };
        expect((await invoke(["bootstrap", "reissue-first-activation"])).code).not.toBe(0);
        const run = await invoke(["bootstrap", "reissue-first-activation", file]);
        expect(run.code, run.stderr).toBe(0);
        const receipt = JSON.parse(run.stdout) as {
          command: string;
          mode: string;
          status: string;
          secretOnce: boolean;
          grantId: string;
          staleChallengeId: string;
          restartUrl: string;
        };
        expect(receipt).toMatchObject({
          command: "bootstrap",
          mode: "reissue-first-activation",
          status: "restart_issued",
          secretOnce: true,
          staleChallengeId: pending.activationChallengeId
        });
        const link = new URL(receipt.restartUrl);
        expect(link.origin).toBe(f.origin);
        expect(link.pathname).toBe("/enroll/restart");
        expect(link.hash).toHaveLength(44);
        // A second live handoff for the same person refuses.
        expect((await invoke(["bootstrap", "reissue-first-activation", file])).code).not.toBe(0);

        const restartPage = await person.get("/enroll/restart");
        const restartCommon = {
          csrf_token: csrfOf(await restartPage.text()),
          restart_token: link.hash.slice(1)
        };
        const restartBegun = await person.post("/enroll/restart/passkey/begin", restartCommon);
        expect(
          restartBegun.status,
          (await restartBegun.clone().text()) + f.errors.map((error) => error.stack).join("\n")
        ).toBe(200);
        const restartOptions = (await restartBegun.json()) as { publicKey: { challenge: string } };
        const restartDone = await person.post("/enroll/restart/passkey/complete", {
          ...restartCommon,
          credential: JSON.stringify(auth.assertion(restartOptions.publicKey.challenge, f.origin))
        });
        expect(
          restartDone.status,
          (await restartDone.clone().text()) + f.errors.map((error) => error.stack).join("\n")
        ).toBe(200);
        const fresh = (await restartDone.json()) as {
          activationChallengeId: string;
          activationCode: string;
        };
        expect(fresh.activationChallengeId).not.toBe(pending.activationChallengeId);
        // The stale code activates nothing: the old challenge is revoked, and the stale
        // digits only count as one failed attempt against the fresh challenge.
        expect(
          await f.operator.activateFirstSecretary({
            activationCode: pending.activationCode,
            proofingMethod: "in_person"
          })
        ).toMatchObject({ activated: false, reason: "code_mismatch", attemptCount: 1 });
        expect(
          (
            await pool.query("select state from enrollment_activation_challenges where id=$1", [
              pending.activationChallengeId
            ])
          ).rows
        ).toEqual([{ state: "revoked" }]);
        expect(
          await f.operator.activateFirstSecretary({
            activationCode: fresh.activationCode,
            proofingMethod: "in_person"
          })
        ).toMatchObject({ activated: true });
        expect(
          (await pool.query("select state from members where id=$1", [first.firstMemberId])).rows
        ).toEqual([{ state: "active" }]);
      } finally {
        await rm(directory, { recursive: true, force: true });
        await f.close();
      }
    });
  }, 60_000);
});
