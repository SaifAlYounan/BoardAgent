import { execFile } from "node:child_process";
import { lstat } from "node:fs/promises";
import { promisify } from "node:util";

const execute = promisify(execFile);

/** A private host input must belong to the numeric container principal on native Linux. */
export async function ownPrivateContainerInput(image: string, file: string): Promise<void> {
  const metadata = await lstat(file);
  if (!metadata.isFile() || (metadata.mode & 0o077) !== 0) {
    throw new Error("container fixture input must be an owner-only regular file");
  }
  await execute("docker", [
    "run",
    "--rm",
    "--network",
    "none",
    "--read-only",
    "--user",
    "0:0",
    "--cap-drop",
    "ALL",
    "--cap-add",
    "CHOWN",
    "--cap-add",
    "FOWNER",
    "--security-opt",
    "no-new-privileges:true",
    "--mount",
    `type=bind,source=${file},target=/input`,
    "--entrypoint",
    "sh",
    image,
    "-ec",
    "chown 10001:10001 /input && chmod 0400 /input"
  ]);
}

/** Use the exact loopback-published fixture's Docker network; never publish a DB publicly. */
export async function containerDatabaseRoute(baseUrl: string): Promise<{
  readonly network: string;
  readonly hostname: string;
  readonly port: string;
}> {
  const url = new URL(baseUrl);
  if (url.hostname !== "127.0.0.1" && url.hostname !== "localhost") {
    throw new Error("container database fixture must use host loopback");
  }
  const port = url.port || "5432";
  const { stdout } = await execute("docker", [
    "ps",
    "--filter",
    `publish=${port}`,
    "--format",
    "{{.ID}}"
  ]);
  const ids = stdout.trim().split(/\s+/u).filter(Boolean);
  if (ids.length !== 1) throw new Error("expected exactly one loopback database fixture");
  const inspected = await execute("docker", ["inspect", ids[0]!]);
  const containers = JSON.parse(inspected.stdout) as {
    Name: string;
    Config: { Labels: Record<string, string> };
    NetworkSettings: {
      Ports: Record<string, { HostIp: string; HostPort: string }[]>;
      Networks: Record<string, unknown>;
    };
  }[];
  const container = containers[0]!;
  const bindings = container.NetworkSettings.Ports["5432/tcp"];
  const networks = Object.keys(container.NetworkSettings.Networks);
  if (
    container.Config.Labels["com.docker.compose.service"] !== "postgres" ||
    !bindings?.some((binding) => binding.HostIp === "127.0.0.1" && binding.HostPort === port) ||
    bindings.some((binding) => binding.HostIp !== "127.0.0.1") ||
    networks.length !== 1
  ) {
    throw new Error("database fixture is not the expected private Compose PostgreSQL service");
  }
  return { network: networks[0]!, hostname: container.Name.replace(/^\//u, ""), port: "5432" };
}
