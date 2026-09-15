import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

async function source(path: string): Promise<string> {
  return readFile(new URL(`../../${path}`, import.meta.url), "utf8");
}

describe("reproducible VPS container skeleton", () => {
  it("pins every base image by full multi-platform digest", async () => {
    const dockerfile = await source("Dockerfile");
    const compose = await source("compose.yaml");
    expect(dockerfile).toContain(
      "node:24.20.0-alpine3.24@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf"
    );
    expect(dockerfile).toContain(
      "postgres:18.6-alpine3.24@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2"
    );
    expect(dockerfile).toContain(
      "golang:1.26.6-alpine3.24@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83"
    );
    expect(dockerfile).toContain(
      "alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"
    );
    expect(`${dockerfile}\n${compose}`).not.toMatch(/:\s*latest\b|:latest\b/u);
  });

  it("runs the application without root and hardens the Compose services", async () => {
    const dockerfile = await source("Dockerfile");
    const compose = await source("compose.yaml");
    expect(dockerfile).toContain("USER 10001:10001");
    expect(dockerfile).toContain("AS postgres-runtime");
    expect(dockerfile).toContain("'libcrypto3=3.5.8-r0'");
    expect(dockerfile).toContain("'libssl3=3.5.8-r0'");
    expect(dockerfile).toContain("apk info -e 'libuuid=2.42.3-r1'");
    expect(dockerfile).toContain('rm -f "${libuuid_apk}" /usr/local/bin/gosu');
    expect(dockerfile).toContain("USER 70:70");
    expect(compose).toContain("target: postgres-runtime");
    expect(compose).toContain("${POSTGRES_IMAGE:-boardagent-postgres:local}");
    expect(dockerfile).toContain("AS caddy-runtime");
    expect(dockerfile).toContain("golang.org/x/crypto@v0.55.0");
    expect(dockerfile).toContain("golang.org/x/net@v0.58.0");
    expect(dockerfile).toContain("golang.org/x/text@v0.41.0");
    expect(dockerfile).toContain("google.golang.org/grpc@v1.83.2");
    expect(dockerfile).toContain("USER 10002:10002");
    expect(compose).toContain("target: caddy-runtime");
    expect(compose).toContain("${CADDY_IMAGE:-boardagent-caddy:local}");
    expect(compose).toContain("read_only: true");
    expect(compose).toContain("no-new-privileges:true");
    expect(compose).toContain("cap_drop:");
    const postgresSection = compose.split("  postgres:\n")[1]?.split("\n  server:\n")[0];
    expect(postgresSection).toBeDefined();
    expect(postgresSection).toContain('user: "70:70"');
    expect(postgresSection).toContain("/var/run/postgresql:size=16m,mode=0775,uid=70,gid=70");
    expect(postgresSection).not.toContain("cap_add:");
    expect(compose).toContain('profiles: ["https"]');
  });

  it("verifies the patched PostgreSQL libuuid package for each supported architecture", async () => {
    const dockerfile = await source("Dockerfile");
    expect(dockerfile).toContain("ARG TARGETARCH");
    expect(dockerfile).toContain("amd64) alpine_arch=x86_64");
    expect(dockerfile).toContain("arm64) alpine_arch=aarch64");
    expect(dockerfile).toContain(
      "8306e5bb577696c9069fe1dfd9e1dcc39d2d481c6a1b0e707fd03c3e21aa6aa2"
    );
    expect(dockerfile).toContain(
      "9ce20c7ffe2ccaa7c321893c10564abbca13c3f2edb82f60a35f1f68e004f86c"
    );
    expect(dockerfile).toContain(
      "https://dl-cdn.alpinelinux.org/alpine/v3.24/main/${alpine_arch}/libuuid-2.42.3-r1.apk"
    );
    expect(dockerfile).toContain("sha256sum -c -");
    expect(dockerfile).toContain("apk verify --keys-dir /etc/apk/keys");
    expect(dockerfile).toContain("unsupported TARGETARCH");
  });

  it("keeps the hostile prior-art tree outside the image context", async () => {
    expect(await source(".dockerignore")).toMatch(/^vendor\/openboard$/mu);
  });

  it("keeps ignored review evidence and local scratch outside the release image context", async () => {
    const excluded = await source(".dockerignore");
    expect(excluded).toMatch(/^artifacts\/review$/mu);
    expect(excluded).toMatch(/^tmp$/mu);
    expect(excluded).toMatch(/^tests\/\.net-stamp\.json$/mu);
    expect(excluded).toMatch(/^tests\/\.net-lastrun\.json$/mu);
  });

  it("exposes the Phase 1 database only on a loopback test override", async () => {
    const base = await source("compose.yaml");
    const test = await source("compose.test.yaml");
    const postgresSection = base.split("  postgres:\n")[1]?.split("\n  server:\n")[0];
    expect(postgresSection).toBeDefined();
    expect(postgresSection).not.toContain("ports:");
    expect(test).toContain('"127.0.0.1:${BOARDAGENT_TEST_POSTGRES_PORT:-55432}:5432"');
  });

  it("keeps webhook delivery off and the worker private in the default composition", async () => {
    const [base, production, environment] = await Promise.all([
      source("compose.yaml"),
      source("compose.production.yaml"),
      source(".env.production.example")
    ]);
    const worker = base.split("  worker:\n")[1]?.split("\n  caddy-volume-init:\n")[0];
    expect(worker).toBeDefined();
    expect(worker).toContain("networks: [backend]");
    expect(worker).not.toMatch(/^    (?:ports|network_mode):/mu);
    expect(base).toMatch(/^  backend:\n    internal: true$/mu);
    expect(`${base}\n${production}`).not.toContain("webhook-egress");
    expect(environment).toMatch(/^BOARDAGENT_WEBHOOKS_ENABLED=false$/mu);
  });

  it("offers outbound webhook routing only through an explicit worker-only overlay", async () => {
    const overlay = await source("compose.webhooks.yaml");
    const sections = overlay.split(/^networks:\n/mu);
    expect(sections).toHaveLength(2);
    expect(sections[0]?.match(/^  [a-z][a-z0-9-]*:$/gmu)).toEqual(["  worker:"]);
    expect(sections[0]).toContain("networks: [backend, webhook-egress]");
    expect(sections[1]?.match(/^  [a-z][a-z0-9-]*:$/gmu)).toEqual(["  webhook-egress:"]);
    expect(sections[1]).toContain("driver: bridge");
    expect(sections[1]).toContain("internal: false");
    expect(overlay).not.toMatch(/^\s*(?:ports|network_mode|environment|privileged|cap_add):/mu);
    expect(overlay).not.toContain("BOARDAGENT_WEBHOOKS_ENABLED");
  });

  it("adds the explicit recovery overlay without weakening the default private network", async () => {
    const base = await source("compose.yaml");
    const recovery = await source("compose.recovery.yaml");
    const archiveScript = await source("ops/postgres/archive-wal.sh");
    const hba = await source("ops/postgres/pg_hba.conf");

    expect(base).toContain("internal: true");
    expect(recovery).toContain("archive_mode=on");
    expect(recovery).toContain("archive_timeout=900s");
    expect(recovery).toContain("wal_keep_size=2048MB");
    expect(recovery).toContain('group_add: ["10001"]');
    expect(recovery).toContain("-m 2770 /wal-staging");
    expect(recovery).toContain("boardagent-archive-wal");
    expect(base).toContain("${RELEASE_IMAGE:-boardagent:local}");
    expect(base).toContain("${APP_ENV_FILE:-.env}");
    expect(recovery).toContain("RECOVERY_ROOT:?");
    expect(recovery).toContain("BACKUP_KEK_HOST_FILE:?");
    expect(recovery).toContain("BACKUP_KEY_ID:?");
    expect(recovery).toContain("BOARDAGENT_BACKUP_KEY_ID: ${BACKUP_KEY_ID:?");
    expect(recovery).toContain("install -o 10001 -g 10001 -m 0400");
    expect(recovery).toContain("read_only: true");
    expect(recovery).toContain("no-new-privileges:true");
    expect(archiveScript).toContain("cmp -s");
    expect(archiveScript).toContain('chmod 0640 "$temporary"');
    expect(archiveScript).toContain("encrypted WAL archive acknowledgement timed out");
    expect(archiveScript).toContain("*.backup)");
    expect(archiveScript).toContain("*.history)");
    expect(archiveScript).toContain("mv --");
    expect(hba).toMatch(/^host\s+replication\s+all\s+all\s+scram-sha-256$/mu);
    expect(hba).not.toMatch(/\btrust\b/u);
  });

  it("keeps production database and key material in purpose-separated owner-only files", async () => {
    const production = await source("compose.production.yaml");
    const environment = await source(".env.production.example");

    expect(production).toContain("environment: !override");
    expect(production).toContain("POSTGRES_PASSWORD_FILE:");
    expect(production).toContain("boardagent_migrator_login@postgres");
    expect(production).toContain("boardagent_server_login@postgres");
    expect(production).toContain("boardagent_worker_login@postgres");
    expect(production).toContain("DATABASE_BACKUP_PASSWORD_FILE:");
    expect(production).toContain('install -o "$$uid" -g "$$uid" -m 0400');
    expect(production).toContain("uid=10001");
    expect(production).toContain("uid=70");
    expect(production).toContain("postgres-secrets:/run/boardagent-postgres-secrets:ro");
    for (const consumer of ["initializer", "operator", "server", "worker"]) {
      expect(production).toContain(`${consumer}-secrets:/run/boardagent-secrets:ro`);
    }
    expect(production).not.toContain("application-secrets:");
    expect(production).not.toMatch(/postgresql:\/\/[^@\s]+:[^@\s]+@/u);
    expect(environment).toContain(
      "BOARDAGENT_OAUTH_SIGNING_KEY_FILE=/run/boardagent-secrets/oauth_signing_key"
    );
    expect(environment).not.toMatch(/(?:PASSWORD|SECRET|KEY)=\S+/u);
  });
});
