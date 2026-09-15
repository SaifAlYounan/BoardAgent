import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { request } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  DEFAULT_POSTGRES_IMAGE,
  DEFAULT_RELEASE_IMAGE,
  SOURCE_TREE_LABEL
} from "../../scripts/src/build-release-image.js";
import { sourceTreeSha256 } from "../../scripts/src/verify-release.js";
import { ownPrivateContainerInput } from "../helpers/container-custody.js";

interface Invocation {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

async function command(
  executable: string,
  args: readonly string[],
  env: NodeJS.ProcessEnv = process.env
): Promise<Invocation> {
  const child = spawn(executable, [...args], {
    cwd: path.resolve("."),
    env,
    stdio: ["ignore", "pipe", "pipe"]
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => (stdout += chunk));
  child.stderr.on("data", (chunk: string) => (stderr += chunk));
  const code = await new Promise<number | null>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", resolve);
  });
  return { code, stdout, stderr };
}

async function waitFor(
  predicate: () => Promise<boolean>,
  description: string,
  timeoutMilliseconds = 60_000
): Promise<void> {
  const deadline = Date.now() + timeoutMilliseconds;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`timed out waiting for ${description}`);
}

async function ready(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const outbound = request(
      {
        hostname: "127.0.0.1",
        port,
        path: "/health/ready",
        headers: {
          host: "cold-start.boardagent.test",
          "x-forwarded-for": "198.51.100.41",
          "x-forwarded-proto": "https"
        }
      },
      (response) => {
        response.resume();
        response.once("end", () => resolve(response.statusCode === 200));
      }
    );
    outbound.once("error", () => resolve(false));
    outbound.end();
  });
}

describe("T9 empty-volume Compose cold start", () => {
  it("boots PostgreSQL, performs the one-use bootstrap, then reaches server and worker readiness", async () => {
    const suffix = `${String(process.pid)}_${randomBytes(4).toString("hex")}`;
    const project = `boardagent_cold_${suffix}`.toLowerCase();
    const working = await mkdtemp(path.join(tmpdir(), "boardagent-cold-start-"));
    const appEnv = path.join(working, "app.env");
    const setup = path.join(working, "bootstrap.json");
    const image = process.env["BOARDAGENT_RELEASE_IMAGE"] ?? DEFAULT_RELEASE_IMAGE;
    const postgresImage = process.env["BOARDAGENT_POSTGRES_IMAGE"] ?? DEFAULT_POSTGRES_IMAGE;
    const password = `cold-${randomBytes(18).toString("base64url")}`;
    const secret = `cold-start-${randomBytes(32).toString("base64url")}`;
    const compose = ["compose", "-p", project, "-f", "compose.yaml"] as const;
    const env = {
      ...process.env,
      APP_ENV_FILE: appEnv,
      POSTGRES_PASSWORD: password,
      PUBLISHED_PORT: "0",
      RELEASE_IMAGE: image,
      POSTGRES_IMAGE: postgresImage
    };
    const appEnvironment = (organizationId?: string): string =>
      [
        "BOARDAGENT_ENV=test",
        `BOARDAGENT_DATABASE_URL=postgresql://boardagent:${encodeURIComponent(password)}@postgres:5432/boardagent`,
        ...(organizationId ? [`BOARDAGENT_ORGANIZATION_ID=${organizationId}`] : []),
        "BOARDAGENT_PUBLIC_BASE_URL=https://cold-start.boardagent.test",
        "BOARDAGENT_AUTHORIZATION_MODE=builtin",
        "BOARDAGENT_BLOB_ROOT=/var/lib/boardagent/blobs",
        `BOARDAGENT_DEV_MASTER_SECRET=${secret}`,
        "BOARDAGENT_TRUSTED_PROXY_HOPS=1",
        "BOARDAGENT_WEBHOOKS_ENABLED=false"
      ].join("\n") + "\n";
    await writeFile(appEnv, appEnvironment(), { mode: 0o600 });
    await writeFile(
      setup,
      `${JSON.stringify({
        organizationLegalName: "Cold Start Test Ltd",
        organizationDisplayName: "Cold Start Test",
        organizationSlug: "cold-start-test",
        timezone: "UTC",
        boardSlug: "main",
        boardName: "Main",
        boardCanonicalPayload: { schemaVersion: "boardagent.board.v1", name: "Main" },
        firstSecretaryLegalName: "Cold Start Secretary",
        firstSecretaryDisplayName: "Secretary",
        votingWeight: 1,
        supportName: "Secretary",
        supportContactMethods: [{ kind: "operator_reference", value: "cold-start-test" }],
        onboardingTermsText: "Review every canonical record before confirming.",
        invitationHandoffMethod: "in person"
      })}\n`,
      { mode: 0o600 }
    );

    try {
      const inspection = await command("docker", [
        "image",
        "inspect",
        image,
        "--format",
        `{{index .Config.Labels "${SOURCE_TREE_LABEL}"}}`
      ]);
      expect(inspection.code, inspection.stderr).toBe(0);
      expect(inspection.stdout.trim()).toBe(await sourceTreeSha256());

      const database = await command("docker", [...compose, "up", "-d", "postgres"], env);
      expect(database.code, `${database.stdout}\n${database.stderr}`).toBe(0);
      await waitFor(async () => {
        const health = await command(
          "docker",
          [
            ...compose,
            "exec",
            "-T",
            "postgres",
            "pg_isready",
            "-h",
            "127.0.0.1",
            "-U",
            "boardagent"
          ],
          env
        );
        return health.code === 0;
      }, "empty PostgreSQL volume initialization");

      await ownPrivateContainerInput(image, setup);
      const bootstrap = await command(
        "docker",
        [
          ...compose,
          "run",
          "--rm",
          "--no-deps",
          "--volume",
          `${setup}:/tmp/bootstrap.json:ro`,
          "server",
          "node",
          "scripts/dist/operator.js",
          "bootstrap",
          "/tmp/bootstrap.json"
        ],
        env
      );
      expect(bootstrap.code, `${bootstrap.stdout}\n${bootstrap.stderr}`).toBe(0);
      const receipt = JSON.parse(bootstrap.stdout) as Record<string, unknown>;
      expect(receipt).toMatchObject({
        operatorStatus: "succeeded",
        status: "created",
        runtimeKeysRegistered: true,
        secretOnce: true
      });
      const organizationId = String(receipt["organizationId"]);
      expect(organizationId).toMatch(/^[0-9a-f-]{36}$/u);
      await writeFile(appEnv, appEnvironment(organizationId), { mode: 0o600 });

      const application = await command(
        "docker",
        [...compose, "up", "-d", "--no-build", "server", "worker"],
        env
      );
      expect(application.code, `${application.stdout}\n${application.stderr}`).toBe(0);
      const portResult = await command("docker", [...compose, "port", "server", "8787"], env);
      expect(portResult.code, portResult.stderr).toBe(0);
      const port = Number(portResult.stdout.trim().split(":").at(-1));
      expect(Number.isSafeInteger(port) && port > 0).toBe(true);
      await waitFor(() => ready(port), "cold-start server readiness");
      await waitFor(async () => {
        const logs = await command("docker", [...compose, "logs", "--no-color", "worker"], env);
        return (
          logs.code === 0 && `${logs.stdout}${logs.stderr}`.includes('"event":"worker.started"')
        );
      }, "cold-start worker readiness");

      const secondBootstrap = await command(
        "docker",
        [
          ...compose,
          "run",
          "--rm",
          "--no-deps",
          "--volume",
          `${setup}:/tmp/bootstrap.json:ro`,
          "server",
          "node",
          "scripts/dist/operator.js",
          "bootstrap",
          "/tmp/bootstrap.json"
        ],
        env
      );
      expect(secondBootstrap.code, secondBootstrap.stderr).toBe(0);
      expect(JSON.parse(secondBootstrap.stdout)).toMatchObject({
        status: "already_initialized",
        secretOnce: true
      });
    } finally {
      await command("docker", [...compose, "down", "--volumes", "--remove-orphans"], env).catch(
        () => undefined
      );
      await rm(working, { recursive: true, force: true });
    }
  }, 180_000);
});
