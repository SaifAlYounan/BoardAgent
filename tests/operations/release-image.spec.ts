import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { request } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import { DEFAULT_RELEASE_IMAGE, SOURCE_TREE_LABEL } from "../../scripts/src/build-release-image.js";
import { sourceTreeSha256 } from "../../scripts/src/verify-release.js";
import { containerDatabaseRoute, ownPrivateContainerInput } from "../helpers/container-custody.js";

const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
const IMAGE = process.env["BOARDAGENT_RELEASE_IMAGE"] ?? DEFAULT_RELEASE_IMAGE;
const ORIGIN = "https://boardagent.image.test";

async function command(
  executable: string,
  args: readonly string[]
): Promise<{
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}> {
  const child = spawn(executable, [...args], { stdio: ["ignore", "pipe", "pipe"] });
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

async function health(port: number): Promise<{ readonly status: number; readonly body: string }> {
  return new Promise((resolve, reject) => {
    const outbound = request(
      {
        hostname: "127.0.0.1",
        port,
        path: "/health/ready",
        headers: {
          host: new URL(ORIGIN).host,
          "x-forwarded-for": "198.51.100.30",
          "x-forwarded-proto": "https"
        }
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.once("end", () =>
          resolve({
            status: response.statusCode ?? 0,
            body: Buffer.concat(chunks).toString("utf8")
          })
        );
      }
    );
    outbound.once("error", reject);
    outbound.end();
  });
}

async function waitForHealthy(name: string): Promise<void> {
  const deadline = Date.now() + 45_000;
  while (Date.now() < deadline) {
    const inspected = await command("docker", [
      "inspect",
      "--format",
      "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
      name
    ]);
    if (inspected.stdout.trim() === "healthy") return;
    if (inspected.stdout.trim() === "unhealthy" || inspected.code !== 0) {
      throw new Error("release image became unhealthy");
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error("release image did not become healthy within 45 seconds");
}

describe("T9 local release image", () => {
  it("binds the exact source and runs both nonroot services read-only with clean SIGTERM", async () => {
    const suffix = `${String(process.pid)}_${randomBytes(4).toString("hex")}`;
    const database = `boardagent_image_${suffix}`;
    const container = `boardagent-image-${suffix.replaceAll("_", "-")}`;
    const workerContainer = `boardagent-worker-image-${suffix.replaceAll("_", "-")}`;
    const adminUrl = new URL(BASE_URL);
    adminUrl.pathname = "/postgres";
    const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
    await admin.query(`create database "${database}"`);
    const directory = await mkdtemp(path.join(tmpdir(), "boardagent-image-"));
    const setupPath = path.join(directory, "bootstrap.json");
    const envPath = path.join(directory, "runtime.env");
    await writeFile(
      setupPath,
      `${JSON.stringify({
        organizationLegalName: "Image Test Ltd",
        organizationDisplayName: "Image Test",
        organizationSlug: "image-test",
        timezone: "UTC",
        boardSlug: "main",
        boardName: "Main",
        boardCanonicalPayload: { schemaVersion: "boardagent.board.v1", name: "Main" },
        firstSecretaryLegalName: "Secretary",
        firstSecretaryDisplayName: "Secretary",
        votingWeight: 1,
        supportName: "Secretary",
        supportContactMethods: [{ kind: "operator_reference", value: "local" }],
        onboardingTermsText: "Review every canonical record.",
        invitationHandoffMethod: "in person"
      })}\n`,
      { mode: 0o600 }
    );
    const route = await containerDatabaseRoute(BASE_URL);
    const containerUrl = new URL(BASE_URL);
    containerUrl.hostname = route.hostname;
    containerUrl.port = route.port;
    containerUrl.pathname = `/${database}`;
    const databaseUrl = containerUrl.toString();
    const secret = "release-image-test-secret-material-is-long-enough";
    const envLines = (organizationId?: string): string =>
      [
        "BOARDAGENT_ENV=test",
        `BOARDAGENT_DATABASE_URL=${databaseUrl}`,
        ...(organizationId ? [`BOARDAGENT_ORGANIZATION_ID=${organizationId}`] : []),
        `BOARDAGENT_PUBLIC_BASE_URL=${ORIGIN}`,
        "BOARDAGENT_AUTHORIZATION_MODE=builtin",
        "BOARDAGENT_BLOB_ROOT=/var/lib/boardagent/blobs",
        `BOARDAGENT_DEV_MASTER_SECRET=${secret}`,
        "BOARDAGENT_TRUSTED_PROXY_HOPS=1",
        "BOARDAGENT_WEBHOOKS_ENABLED=false"
      ].join("\n") + "\n";
    await writeFile(envPath, envLines(), { mode: 0o600 });
    let started = false;
    let workerStarted = false;
    try {
      const imageInspection = await command("docker", ["image", "inspect", IMAGE]);
      expect(imageInspection.code, imageInspection.stderr).toBe(0);
      const image = JSON.parse(imageInspection.stdout) as readonly {
        readonly Id?: string;
        readonly Config?: { readonly Labels?: Readonly<Record<string, string>> | null } | null;
      }[];
      expect(image).toHaveLength(1);
      expect(image[0]?.Id).toMatch(/^sha256:[0-9a-f]{64}$/u);
      expect(image[0]?.Config?.Labels?.[SOURCE_TREE_LABEL]).toBe(await sourceTreeSha256());
      for (const tool of [
        "pg_dump",
        "pg_restore",
        "pg_basebackup",
        "pg_verifybackup",
        "pg_controldata"
      ]) {
        const version = await command("docker", [
          "run",
          "--rm",
          "--entrypoint",
          tool,
          IMAGE,
          "--version"
        ]);
        expect(version.code, version.stderr).toBe(0);
        expect(version.stdout).toContain("PostgreSQL) 18.6");
      }
      for (const excluded of ["/app/.stryker-tmp", "/app/vendor/openboard"]) {
        const absent = await command("docker", [
          "run",
          "--rm",
          "--entrypoint",
          "/usr/bin/test",
          IMAGE,
          "!",
          "-e",
          excluded
        ]);
        expect(absent.code, absent.stderr).toBe(0);
      }

      await ownPrivateContainerInput(IMAGE, setupPath);
      const bootstrap = await command("docker", [
        "run",
        "--rm",
        "--network",
        route.network,
        "--env-file",
        envPath,
        "--mount",
        `type=bind,source=${setupPath},target=/tmp/bootstrap.json,readonly`,
        "--entrypoint",
        "node",
        IMAGE,
        "scripts/dist/operator.js",
        "bootstrap",
        "/tmp/bootstrap.json"
      ]);
      expect(bootstrap.code, bootstrap.stderr).toBe(0);
      const receipt = JSON.parse(bootstrap.stdout) as Record<string, unknown>;
      expect(receipt).toMatchObject({
        operatorStatus: "succeeded",
        status: "created",
        runtimeKeysRegistered: true
      });
      await writeFile(envPath, envLines(String(receipt["organizationId"])), { mode: 0o600 });

      const launched = await command("docker", [
        "run",
        "--detach",
        "--network",
        route.network,
        "--name",
        container,
        "--env-file",
        envPath,
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--publish",
        "127.0.0.1::8787",
        IMAGE
      ]);
      expect(launched.code, launched.stderr).toBe(0);
      started = true;
      await waitForHealthy(container);
      const portResult = await command("docker", ["port", container, "8787/tcp"]);
      expect(portResult.code, portResult.stderr).toBe(0);
      const port = Number(portResult.stdout.trim().split(":").at(-1));
      expect(Number.isInteger(port) && port > 0).toBe(true);
      const ready = await health(port);
      expect(ready.status).toBe(200);
      expect(JSON.parse(ready.body)).toEqual({ status: "ready" });

      const workerLaunch = await command("docker", [
        "run",
        "--detach",
        "--network",
        route.network,
        "--name",
        workerContainer,
        "--env-file",
        envPath,
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "--tmpfs",
        "/var/lib/boardagent/blobs:rw,noexec,nosuid,size=64m",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        IMAGE,
        "node",
        "artifacts/server/dist/main.js",
        "worker"
      ]);
      expect(workerLaunch.code, workerLaunch.stderr).toBe(0);
      workerStarted = true;
      const workerDeadline = Date.now() + 30_000;
      let workerLogs = "";
      while (Date.now() < workerDeadline) {
        const observed = await command("docker", ["logs", workerContainer]);
        workerLogs = `${observed.stdout}${observed.stderr}`;
        if (workerLogs.includes('"event":"worker.started"')) break;
        const state = await command("docker", [
          "inspect",
          "--format",
          "{{.State.Running}} {{.State.ExitCode}}",
          workerContainer
        ]);
        if (!state.stdout.trim().startsWith("true ")) {
          throw new Error(`release worker exited before startup: ${workerLogs}`);
        }
        await new Promise((resolve) => setTimeout(resolve, 250));
      }
      expect(workerLogs).toContain('"event":"worker.started"');

      const workerStopped = await command("docker", ["stop", "--time", "30", workerContainer]);
      expect(workerStopped.code, workerStopped.stderr).toBe(0);
      workerStarted = false;
      const workerExit = await command("docker", [
        "inspect",
        "--format",
        "{{.State.ExitCode}} {{.Config.User}}",
        workerContainer
      ]);
      expect(workerExit.stdout.trim()).toBe("0 10001:10001");
      const stoppedWorkerLogs = await command("docker", ["logs", workerContainer]);
      expect(`${stoppedWorkerLogs.stdout}${stoppedWorkerLogs.stderr}`).toContain(
        '"event":"worker.stopped"'
      );
      expect(`${stoppedWorkerLogs.stdout}${stoppedWorkerLogs.stderr}`).not.toContain(secret);

      const stopped = await command("docker", ["stop", "--time", "30", container]);
      expect(stopped.code, stopped.stderr).toBe(0);
      started = false;
      const exit = await command("docker", [
        "inspect",
        "--format",
        "{{.State.ExitCode}} {{.Config.User}}",
        container
      ]);
      expect(exit.stdout.trim()).toBe("0 10001:10001");
      const logs = await command("docker", ["logs", container]);
      expect(logs.stderr).toContain('"event":"server.started"');
      expect(logs.stderr).toContain('"event":"server.stopped"');
      expect(logs.stderr).not.toContain(secret);
    } finally {
      if (workerStarted) await command("docker", ["rm", "--force", workerContainer]);
      else await command("docker", ["rm", workerContainer]);
      if (started) await command("docker", ["rm", "--force", container]);
      else await command("docker", ["rm", container]);
      await admin.query(`drop database "${database}" with (force)`);
      await admin.end();
      await rm(directory, { recursive: true, force: true });
    }
  }, 120_000);
});
