import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { get, request, type IncomingHttpHeaders } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  DEFAULT_CADDY_IMAGE,
  RELEASE_COMPONENT_LABEL,
  SOURCE_TREE_LABEL
} from "../../scripts/src/build-release-image.js";
import { sourceTreeSha256 } from "../../scripts/src/verify-release.js";

const IMAGE = process.env["BOARDAGENT_CADDY_IMAGE"] ?? DEFAULT_CADDY_IMAGE;

/**
 * The production `Caddyfile` header lines, verbatim: one `?` default per header (a block of
 * several `?` defaults applies only when every listed header is absent), never an override.
 */
const PRODUCTION_HEADER_BLOCK =
  '\theader ?Strict-Transport-Security "max-age=31536000; includeSubDomains"\n' +
  '\theader ?X-Content-Type-Options "nosniff"\n' +
  '\theader ?X-Frame-Options "DENY"\n' +
  '\theader ?Referrer-Policy "no-referrer"\n' +
  '\theader ?Permissions-Policy "camera=(), geolocation=(), microphone=()"\n' +
  "\theader -Server";

async function readResponse(
  port: number,
  requestPath: string
): Promise<{ readonly status: number; readonly headers: IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const request = get({ host: "127.0.0.1", port, path: requestPath }, (response) => {
      response.resume();
      response.once("end", () =>
        resolve({ status: response.statusCode ?? 0, headers: response.headers })
      );
    });
    request.once("error", reject);
  });
}

async function waitForResponse(
  port: number,
  requestPath: string
): Promise<{ readonly status: number; readonly headers: IncomingHttpHeaders }> {
  const deadline = Date.now() + 30_000;
  let last: { readonly status: number; readonly headers: IncomingHttpHeaders } | undefined;
  while (Date.now() < deadline) {
    try {
      last = await readResponse(port, requestPath);
      if (last.status === 200) return last;
    } catch {
      // the proxy or its upstream is still starting
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(`timed out waiting for ${requestPath}: ${JSON.stringify(last)}`);
}

interface Invocation {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

async function command(executable: string, args: readonly string[]): Promise<Invocation> {
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

async function readReady(port: number): Promise<{
  readonly status: number;
  readonly body: string;
  readonly contentType: string | undefined;
}> {
  return new Promise((resolve, reject) => {
    const outbound = request({ hostname: "127.0.0.1", port, path: "/ready" }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.once("end", () =>
        resolve({
          status: response.statusCode ?? 0,
          body: Buffer.concat(chunks).toString("utf8"),
          contentType: response.headers["content-type"]
        })
      );
    });
    outbound.once("error", reject);
    outbound.end();
  });
}

async function waitForReady(
  port: number
): Promise<ReturnType<typeof readReady> extends Promise<infer T> ? T : never> {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    try {
      return await readReady(port);
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
  }
  throw new Error("timed out waiting for hardened Caddy runtime");
}

describe("T9 hardened Caddy runtime", () => {
  it("is exact-source, nonroot and read-only while serving with the patched binary", async () => {
    const suffix = `${String(process.pid)}-${randomBytes(4).toString("hex")}`;
    const container = `boardagent-caddy-${suffix}`;
    const working = await mkdtemp(path.join(tmpdir(), "boardagent-caddy-runtime-"));
    const caddyfile = path.join(working, "Caddyfile");
    await writeFile(
      caddyfile,
      `{\n\tadmin off\n\tauto_https off\n}\n\n:8080 {\n\theader Content-Type text/plain\n\trespond /ready "ready" 200\n}\n`,
      { mode: 0o644 }
    );
    // This public synthetic configuration is readable by Caddy even under launch umask 0077.
    await chmod(caddyfile, 0o644);
    try {
      const inspection = await command("docker", ["image", "inspect", IMAGE]);
      expect(inspection.code, inspection.stderr).toBe(0);
      const images = JSON.parse(inspection.stdout) as readonly {
        readonly Config?: {
          readonly User?: string;
          readonly Labels?: Readonly<Record<string, string>> | null;
        } | null;
      }[];
      expect(images).toHaveLength(1);
      expect(images[0]?.Config?.User).toBe("10002:10002");
      expect(images[0]?.Config?.Labels?.[SOURCE_TREE_LABEL]).toBe(await sourceTreeSha256());
      expect(images[0]?.Config?.Labels?.[RELEASE_COMPONENT_LABEL]).toBe("caddy");

      const provenance = await command("docker", [
        "run",
        "--rm",
        "--entrypoint",
        "sh",
        IMAGE,
        "-ec",
        'test "$(id -u):$(id -g)" = 10002:10002; caddy version; cat /usr/share/boardagent/caddy-build-info.txt'
      ]);
      expect(provenance.code, provenance.stderr).toBe(0);
      expect(provenance.stdout).toContain("v2.11.4+boardagent.2");
      expect(provenance.stdout).toContain("go1.26.6");
      expect(provenance.stdout).toContain("golang.org/x/crypto\tv0.55.0");
      expect(provenance.stdout).toContain("golang.org/x/net\tv0.58.0");
      expect(provenance.stdout).toContain("golang.org/x/text\tv0.41.0");
      expect(provenance.stdout).toContain("google.golang.org/grpc\tv1.83.2");

      const started = await command("docker", [
        "run",
        "--detach",
        "--name",
        container,
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16m",
        "--tmpfs",
        "/config:rw,noexec,nosuid,size=16m,uid=10002,gid=10002",
        "--tmpfs",
        "/data:rw,noexec,nosuid,size=16m,uid=10002,gid=10002",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--publish",
        "127.0.0.1::8080",
        "--mount",
        `type=bind,source=${caddyfile},target=/etc/caddy/Caddyfile,readonly`,
        IMAGE
      ]);
      expect(started.code, started.stderr).toBe(0);
      const portResult = await command("docker", ["port", container, "8080/tcp"]);
      expect(portResult.code, portResult.stderr).toBe(0);
      const port = Number(portResult.stdout.trim().split(":").at(-1));
      expect(Number.isSafeInteger(port) && port > 0).toBe(true);
      const ready = await waitForReady(port);
      expect(ready).toEqual({ status: 200, body: "ready", contentType: "text/plain" });
      const stopped = await command("docker", ["stop", "--time", "10", container]);
      expect(stopped.code, stopped.stderr).toBe(0);
      const exitCode = await command("docker", [
        "inspect",
        "--format",
        "{{.State.ExitCode}}",
        container
      ]);
      expect(exitCode.code, exitCode.stderr).toBe(0);
      expect(exitCode.stdout.trim()).toBe("0");
    } finally {
      await command("docker", ["rm", "-f", container]).catch(() => undefined);
      await rm(working, { recursive: true, force: true });
    }
  }, 60_000);

  it("lets application security headers pass through and fills only the ones left unset", async () => {
    // The first real Claude Code login (14 September 2026) failed because the production
    // Caddyfile overwrote the auth pages' `Referrer-Policy: same-origin` with
    // `no-referrer`; current Chromium then sends `Origin: null` on the passkey form
    // submission and the CSRF origin check refuses it. The production header block is
    // pinned here verbatim and exercised through the real proxy against an upstream.
    const productionCaddyfile = await readFile(path.resolve("Caddyfile"), "utf8");
    expect(productionCaddyfile).toContain(PRODUCTION_HEADER_BLOCK);
    expect(productionCaddyfile).toContain("reverse_proxy server:8787");
    const suffix = `${String(process.pid)}-${randomBytes(4).toString("hex")}`;
    const network = `boardagent-caddy-net-${suffix}`;
    const upstream = `boardagent-caddy-upstream-${suffix}`;
    const proxy = `boardagent-caddy-proxy-${suffix}`;
    const working = await mkdtemp(path.join(tmpdir(), "boardagent-caddy-headers-"));
    const upstreamFile = path.join(working, "upstream.Caddyfile");
    const proxyFile = path.join(working, "proxy.Caddyfile");
    await writeFile(
      upstreamFile,
      "{\n\tadmin off\n\tauto_https off\n}\n\n:8080 {\n" +
        '\theader /app Referrer-Policy "same-origin"\n' +
        '\theader /app Strict-Transport-Security "max-age=63072000; includeSubDomains"\n' +
        '\theader /app Permissions-Policy "publickey-credentials-get=(self)"\n' +
        '\trespond /app "app" 200\n\trespond /plain "plain" 200\n}\n',
      { mode: 0o644 }
    );
    await writeFile(
      proxyFile,
      "{\n\tadmin off\n\tauto_https off\n}\n\n:8080 {\n\tencode zstd gzip\n" +
        `\treverse_proxy ${upstream}:8080\n\n${PRODUCTION_HEADER_BLOCK}\n}\n`,
      { mode: 0o644 }
    );
    const run = (name: string, caddyfile: string, publish: boolean) =>
      command("docker", [
        "run",
        "--detach",
        "--name",
        name,
        "--network",
        network,
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16m",
        "--tmpfs",
        "/config:rw,noexec,nosuid,size=16m,uid=10002,gid=10002",
        "--tmpfs",
        "/data:rw,noexec,nosuid,size=16m,uid=10002,gid=10002",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        ...(publish ? ["--publish", "127.0.0.1::8080"] : []),
        "--mount",
        `type=bind,source=${caddyfile},target=/etc/caddy/Caddyfile,readonly`,
        IMAGE
      ]);
    try {
      const created = await command("docker", ["network", "create", network]);
      expect(created.code, created.stderr).toBe(0);
      const upstreamStarted = await run(upstream, upstreamFile, false);
      expect(upstreamStarted.code, upstreamStarted.stderr).toBe(0);
      const proxyStarted = await run(proxy, proxyFile, true);
      expect(proxyStarted.code, proxyStarted.stderr).toBe(0);
      const portResult = await command("docker", ["port", proxy, "8080/tcp"]);
      expect(portResult.code, portResult.stderr).toBe(0);
      const port = Number(portResult.stdout.trim().split(":").at(-1));
      expect(Number.isSafeInteger(port) && port > 0).toBe(true);

      const app = await waitForResponse(port, "/app");
      expect(app.status).toBe(200);
      expect(app.headers["referrer-policy"]).toBe("same-origin");
      expect(app.headers["strict-transport-security"]).toBe("max-age=63072000; includeSubDomains");
      expect(app.headers["permissions-policy"]).toBe("publickey-credentials-get=(self)");
      expect(app.headers["x-frame-options"]).toBe("DENY");
      expect(app.headers["x-content-type-options"]).toBe("nosniff");
      expect(app.headers["server"]).toBeUndefined();

      const plain = await waitForResponse(port, "/plain");
      expect(plain.status).toBe(200);
      expect(plain.headers["referrer-policy"]).toBe("no-referrer");
      expect(plain.headers["strict-transport-security"]).toBe(
        "max-age=31536000; includeSubDomains"
      );
      expect(plain.headers["permissions-policy"]).toBe("camera=(), geolocation=(), microphone=()");
      expect(plain.headers["x-frame-options"]).toBe("DENY");
      expect(plain.headers["x-content-type-options"]).toBe("nosniff");
      expect(plain.headers["server"]).toBeUndefined();
    } finally {
      await command("docker", ["rm", "-f", proxy, upstream]).catch(() => undefined);
      await command("docker", ["network", "rm", network]).catch(() => undefined);
      await rm(working, { recursive: true, force: true });
    }
  }, 90_000);
});
