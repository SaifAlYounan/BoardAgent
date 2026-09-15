import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { expect } from "vitest";
import {
  DEFAULT_POSTGRES_IMAGE,
  DEFAULT_RELEASE_IMAGE
} from "../../scripts/src/build-release-image.js";

interface Invocation {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

export async function command(
  executable: string,
  args: readonly string[],
  input?: string
): Promise<Invocation> {
  const child = spawn(executable, [...args], {
    stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"]
  });
  if (input !== undefined) {
    child.stdin?.on("error", () => undefined);
    child.stdin?.end(input);
  }
  let stdout = "";
  let stderr = "";
  child.stdout!.setEncoding("utf8");
  child.stderr!.setEncoding("utf8");
  child.stdout!.on("data", (chunk: string) => (stdout += chunk));
  child.stderr!.on("data", (chunk: string) => (stderr += chunk));
  const code = await new Promise<number | null>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", resolve);
  });
  return { code, stdout, stderr };
}

export function databaseConnection(
  baseUrl: string,
  database: string,
  container: false | { readonly hostname: string; readonly port: string }
): string {
  const url = new URL(baseUrl);
  if (container) {
    url.hostname = container.hostname;
    url.port = container.port;
  }
  url.pathname = `/${database}`;
  return url.toString();
}

export async function withIsolatedRecoveryDatabase(
  run: (
    baseUrl: string,
    route: { network: string; hostname: string; port: string; maintenanceVolume: string }
  ) => Promise<void>
): Promise<void> {
  const directory = await mkdtemp(path.join(tmpdir(), "boardagent-production-recovery-"));
  const project = `boardagent_prod_recovery_${process.pid}_${randomBytes(4).toString("hex")}`;
  const override = path.join(directory, "compose.json");
  const password = randomBytes(32).toString("base64url");
  await writeFile(
    override,
    JSON.stringify({
      services: {
        "maintenance-lock-init": {
          image: process.env["BOARDAGENT_RELEASE_IMAGE"] ?? DEFAULT_RELEASE_IMAGE
        },
        postgres: {
          image: process.env["BOARDAGENT_POSTGRES_IMAGE"] ?? DEFAULT_POSTGRES_IMAGE,
          environment: { POSTGRES_PASSWORD: password },
          ports: ["127.0.0.1::5432"]
        }
      },
      networks: { backend: { internal: false } }
    }),
    { mode: 0o600 }
  );
  const compose = ["compose", "-p", project, "-f", path.resolve("compose.yaml"), "-f", override];
  try {
    const coordinated = await command("docker", [
      ...compose,
      "run",
      "--rm",
      "maintenance-lock-init"
    ]);
    expect(coordinated.code, coordinated.stderr).toBe(0);
    const started = await command("docker", [...compose, "up", "-d", "--wait", "postgres"]);
    expect(started.code, started.stderr).toBe(0);
    const selected = await command("docker", [...compose, "ps", "-q", "postgres"]);
    expect(selected.code, selected.stderr).toBe(0);
    const inspected = await command("docker", ["inspect", selected.stdout.trim()]);
    expect(inspected.code, inspected.stderr).toBe(0);
    const containers = JSON.parse(inspected.stdout) as {
      Name: string;
      Config: { Labels: Record<string, string> };
      NetworkSettings: {
        Ports: Record<string, { HostIp: string; HostPort: string }[]>;
        Networks: Record<string, unknown>;
      };
    }[];
    expect(containers).toHaveLength(1);
    const container = containers[0]!,
      bindings = container.NetworkSettings.Ports["5432/tcp"]!,
      networks = Object.keys(container.NetworkSettings.Networks);
    expect(container.Config.Labels["com.docker.compose.project"]).toBe(project);
    expect(container.Config.Labels["com.docker.compose.service"]).toBe("postgres");
    expect(bindings).toHaveLength(1);
    expect(bindings[0]!.HostIp).toBe("127.0.0.1");
    expect(bindings[0]!.HostPort).toMatch(/^[1-9][0-9]*$/u);
    expect(networks).toHaveLength(1);
    await run(`postgresql://boardagent:${password}@127.0.0.1:${bindings[0]!.HostPort}/boardagent`, {
      network: networks[0]!,
      hostname: container.Name.replace(/^\//u, ""),
      port: "5432",
      maintenanceVolume: `${project}_maintenance-coordination`
    });
  } finally {
    const stopped = await command("docker", [...compose, "down", "--volumes", "--remove-orphans"]);
    expect(stopped.code, stopped.stderr).toBe(0);
    await rm(directory, { recursive: true, force: true });
  }
}
