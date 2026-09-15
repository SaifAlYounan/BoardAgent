import { describe, expect, it } from "vitest";

import {
  assertProductionDatabasePurpose,
  createStructuredLogger,
  parseConfig
} from "../../lib/config/src/index.js";

const local = {
  BOARDAGENT_ENV: "development",
  BOARDAGENT_DATABASE_URL: "postgresql://boardagent:secret@localhost/boardagent",
  BOARDAGENT_ORGANIZATION_ID: "018f0000-0000-7000-8000-000000000001",
  BOARDAGENT_PUBLIC_BASE_URL: "http://127.0.0.1:8787",
  BOARDAGENT_AUTHORIZATION_MODE: "builtin",
  BOARDAGENT_BLOB_ROOT: "/tmp/boardagent-blobs",
  BOARDAGENT_DEV_MASTER_SECRET: "this-is-a-long-local-development-secret"
};
const productionDatabasePassword = "prod_database_password_abcdefghijklmnopqrstuvwxyz0123456789";
const databasePasswordReader = {
  readDatabasePasswordFile: () => productionDatabasePassword
} as const;

describe("fail-closed configuration", () => {
  it("derives separate local keys from one local-only secret", () => {
    const config = parseConfig(local);
    expect(config.organizationId).toBe("018f0000-0000-7000-8000-000000000001");
    expect(config.canonicalResourceUri).toBe("http://127.0.0.1:8787/mcp");
    expect(config.accessTokenTtlSeconds).toBe(900);
    expect(config.exportMaximumBytes).toBe(268_435_456);
    expect(config.exportChunkBytes).toBe(4_194_304);
    const keys = Object.values(config.keySources).map((entry) =>
      Buffer.from(entry).toString("hex")
    );
    expect(new Set(keys).size).toBe(4);
  });

  it("refuses access-token lifetimes above the frozen fifteen-minute ceiling", () => {
    expect(() => parseConfig({ ...local, BOARDAGENT_ACCESS_TOKEN_TTL_SECONDS: "901" })).toThrow();
  });

  it.each(["60", "600", "899"])(
    "refuses an access-token lifetime of %s that issuance cannot honor",
    (seconds) => {
      expect(() => parseConfig({ ...local, BOARDAGENT_ACCESS_TOKEN_TTL_SECONDS: seconds })).toThrow(
        "BOARDAGENT_ACCESS_TOKEN_TTL_SECONDS"
      );
    }
  );

  it.each(["60", "599", "601", "3600"])(
    "refuses a stage lifetime of %s that differs from persisted consent",
    (seconds) => {
      expect(() => parseConfig({ ...local, BOARDAGENT_STAGE_TTL_SECONDS: seconds })).toThrow(
        "BOARDAGENT_STAGE_TTL_SECONDS"
      );
    }
  );

  it("accepts explicit lifetimes matching the issued token and persisted consent", () => {
    expect(
      parseConfig({
        ...local,
        BOARDAGENT_ACCESS_TOKEN_TTL_SECONDS: "900",
        BOARDAGENT_STAGE_TTL_SECONDS: "600"
      })
    ).toMatchObject({ accessTokenTtlSeconds: 900, stageTtlSeconds: 600 });
  });

  it("bounds encrypted export artifacts and database chunk rows", () => {
    expect(() => parseConfig({ ...local, BOARDAGENT_EXPORT_MAX_BYTES: "1048575" })).toThrow();
    expect(() => parseConfig({ ...local, BOARDAGENT_EXPORT_CHUNK_BYTES: "10485761" })).toThrow();
    expect(
      parseConfig({
        ...local,
        BOARDAGENT_EXPORT_MAX_BYTES: "1048576",
        BOARDAGENT_EXPORT_CHUNK_BYTES: "65536"
      })
    ).toMatchObject({ exportMaximumBytes: 1_048_576, exportChunkBytes: 65_536 });
  });

  it("allows insecure HTTP only on a loopback development origin", () => {
    expect(() =>
      parseConfig({ ...local, BOARDAGENT_PUBLIC_BASE_URL: "http://192.0.2.10:8787" })
    ).toThrow("development HTTP public base URL must be loopback");
  });

  it("refuses placeholder-shaped local master secrets", () => {
    expect(() =>
      parseConfig({
        ...local,
        BOARDAGENT_DEV_MASTER_SECRET: "change-me-change-me-change-me-change-me"
      })
    ).toThrow("development master secret cannot be a placeholder");
  });

  it("fails on every unknown BoardAgent variable", () => {
    expect(() => parseConfig({ ...local, BOARDAGENT_DATABASE_UR: "typo" })).toThrow(
      "unknown BoardAgent configuration"
    );
  });

  it("requires one exact UUIDv7 organization binding", () => {
    expect(() => parseConfig({ ...local, BOARDAGENT_ORGANIZATION_ID: undefined })).toThrow(
      "BOARDAGENT_ORGANIZATION_ID"
    );
    expect(() =>
      parseConfig({
        ...local,
        BOARDAGENT_ORGANIZATION_ID: "018f0000-0000-4000-8000-000000000001"
      })
    ).toThrow("BOARDAGENT_ORGANIZATION_ID");
  });

  it("requires HTTPS and four distinct purpose keys in production", () => {
    expect(() =>
      parseConfig({
        ...local,
        BOARDAGENT_ENV: "production",
        BOARDAGENT_DEV_MASTER_SECRET: undefined
      })
    ).toThrow("production public base URL must use HTTPS");
  });

  it("refuses an inline database password in production", () => {
    expect(() =>
      parseConfig(
        {
          ...local,
          BOARDAGENT_ENV: "production",
          BOARDAGENT_PUBLIC_BASE_URL: "https://boardagent.example.com",
          BOARDAGENT_DEV_MASTER_SECRET: undefined,
          BOARDAGENT_OAUTH_SIGNING_KEY_FILE: "/run/secrets/oauth.pem",
          BOARDAGENT_EVIDENCE_SIGNING_KEY_FILE: "/run/secrets/evidence.pem",
          BOARDAGENT_BROWSER_SESSION_KEY_FILE: "/run/secrets/browser.key",
          BOARDAGENT_DATA_KEK_FILE: "/run/secrets/data.key",
          BOARDAGENT_DATABASE_PASSWORD_FILE: "/run/secrets/database-password",
          BOARDAGENT_DATABASE_URL:
            "postgresql://boardagent:boardagent-local-only@postgres:5432/boardagent"
        },
        databasePasswordReader
      )
    ).toThrow("production database password must come from its secret file");
  });

  it("requires an explicit production database principal and password file", () => {
    expect(() =>
      parseConfig({
        ...local,
        BOARDAGENT_ENV: "production",
        BOARDAGENT_PUBLIC_BASE_URL: "https://boardagent.example.com",
        BOARDAGENT_DEV_MASTER_SECRET: undefined,
        BOARDAGENT_OAUTH_SIGNING_KEY_FILE: "/run/secrets/oauth.pem",
        BOARDAGENT_EVIDENCE_SIGNING_KEY_FILE: "/run/secrets/evidence.pem",
        BOARDAGENT_BROWSER_SESSION_KEY_FILE: "/run/secrets/browser.key",
        BOARDAGENT_DATA_KEK_FILE: "/run/secrets/data.key",
        BOARDAGENT_DATABASE_URL: "postgresql://boardagent_server_login@postgres/boardagent"
      })
    ).toThrow("BOARDAGENT_DATABASE_PASSWORD_FILE");
  });

  it("rejects non-canonical public origins and a missing local secret", () => {
    expect(() =>
      parseConfig({ ...local, BOARDAGENT_PUBLIC_BASE_URL: "http://user:pass@127.0.0.1:8787" })
    ).toThrow("credentials/query/fragment");
    expect(() =>
      parseConfig({ ...local, BOARDAGENT_PUBLIC_BASE_URL: "http://127.0.0.1:8787/path" })
    ).toThrow("must not contain a path");
    expect(() =>
      parseConfig({ ...local, BOARDAGENT_PUBLIC_BASE_URL: "ftp://127.0.0.1:8787" })
    ).toThrow("HTTP or HTTPS");
    expect(() => parseConfig({ ...local, BOARDAGENT_DEV_MASTER_SECRET: undefined })).toThrow(
      "requires BOARDAGENT_DEV_MASTER_SECRET"
    );
  });

  it("requires complete OIDC configuration", () => {
    expect(() => parseConfig({ ...local, BOARDAGENT_AUTHORIZATION_MODE: "oidc" })).toThrow(
      "OIDC mode requires"
    );
  });

  it("accepts a fully separated production OIDC profile and canonicalizes its allowlist", () => {
    const production = parseConfig(
      {
        ...local,
        BOARDAGENT_ENV: "production",
        BOARDAGENT_PUBLIC_BASE_URL: "https://boardagent.example.com",
        BOARDAGENT_DATABASE_URL: "postgresql://boardagent_server_login@db/boardagent",
        BOARDAGENT_DATABASE_PASSWORD_FILE: "/run/secrets/database-password",
        BOARDAGENT_AUTHORIZATION_MODE: "oidc",
        BOARDAGENT_DEV_MASTER_SECRET: undefined,
        BOARDAGENT_OAUTH_SIGNING_KEY_FILE: "/run/secrets/oauth.pem",
        BOARDAGENT_EVIDENCE_SIGNING_KEY_FILE: "/run/secrets/evidence.pem",
        BOARDAGENT_BROWSER_SESSION_KEY_FILE: "/run/secrets/browser.key",
        BOARDAGENT_DATA_KEK_FILE: "/run/secrets/data.key",
        BOARDAGENT_OIDC_ISSUER: "https://id.example.com",
        BOARDAGENT_OIDC_CLIENT_ID: "boardagent",
        BOARDAGENT_OIDC_CLIENT_SECRET_FILE: "/run/secrets/oidc-client",
        BOARDAGENT_CLIENT_ALLOWLIST: "client-a, client-b, ,client-a",
        BOARDAGENT_WEBHOOKS_ENABLED: "true"
      },
      databasePasswordReader
    );
    expect(production.canonicalResourceUri).toBe("https://boardagent.example.com/mcp");
    expect(production.oidc).toEqual({
      issuer: "https://id.example.com",
      clientId: "boardagent",
      clientSecretFile: "/run/secrets/oidc-client"
    });
    expect(production.clientAllowlist).toEqual(new Set(["client-a", "client-b"]));
    expect(production.webhooksEnabled).toBe(true);
    expect(new URL(production.databaseUrl)).toMatchObject({
      username: "boardagent_server_login",
      password: productionDatabasePassword
    });
    expect(new Set(Object.values(production.keySources)).size).toBe(4);
    expect(() => assertProductionDatabasePurpose(production, "server")).not.toThrow();
    expect(() => assertProductionDatabasePurpose(production, "worker")).toThrow(
      "boardagent_worker_login"
    );
  });

  it("forbids development secrets and missing or duplicate purpose keys in production", () => {
    const production = {
      ...local,
      BOARDAGENT_ENV: "production",
      BOARDAGENT_PUBLIC_BASE_URL: "https://boardagent.example.com",
      BOARDAGENT_DATABASE_URL: "postgresql://boardagent_server_login@db/boardagent",
      BOARDAGENT_DATABASE_PASSWORD_FILE: "/run/secrets/database-password"
    };
    expect(() => parseConfig(production, databasePasswordReader)).toThrow(
      "forbidden in production"
    );
    expect(() =>
      parseConfig(
        { ...production, BOARDAGENT_DEV_MASTER_SECRET: undefined },
        databasePasswordReader
      )
    ).toThrow("purpose-separated");
    expect(() =>
      parseConfig(
        {
          ...production,
          BOARDAGENT_DEV_MASTER_SECRET: undefined,
          BOARDAGENT_OAUTH_SIGNING_KEY_FILE: "/run/secrets/shared",
          BOARDAGENT_EVIDENCE_SIGNING_KEY_FILE: "/run/secrets/shared",
          BOARDAGENT_BROWSER_SESSION_KEY_FILE: "/run/secrets/browser",
          BOARDAGENT_DATA_KEK_FILE: "/run/secrets/data"
        },
        databasePasswordReader
      )
    ).toThrow("distinct database");
  });
});

describe("safe structured logger", () => {
  it("emits bounded JSON with stable pseudonyms and every safe metric", () => {
    const lines: string[] = [];
    const logger = createStructuredLogger({
      pseudonymKey: Buffer.alloc(32, 0x51),
      service: "boardagent.test",
      clock: () => new Date("2026-09-01T00:00:00Z"),
      sink: (line) => lines.push(line)
    });
    logger.write({ level: "info", event: "started", result: "success" });
    logger.write({
      level: "warn",
      event: "request.denied",
      requestId: "request-1",
      principalId: "person@example.com",
      clientId: "client-secret-name",
      result: "denied",
      reasonCode: "policy.denied",
      surface: "mcp",
      protocol: "2026-07-28",
      durationMs: 12,
      bytes: 34,
      count: 1
    });
    expect(lines).toHaveLength(2);
    const minimal = JSON.parse(lines[0] ?? "{}") as Record<string, unknown>;
    expect(minimal).toEqual({
      schemaVersion: 1,
      timestamp: "2026-09-01T00:00:00.000Z",
      service: "boardagent.test",
      level: "info",
      event: "started",
      result: "success"
    });
    const full = JSON.parse(lines[1] ?? "{}") as Record<string, unknown>;
    expect(full).toMatchObject({
      requestId: "request-1",
      result: "denied",
      reasonCode: "policy.denied",
      surface: "mcp",
      protocol: "2026-07-28",
      durationMs: 12,
      bytes: 34,
      count: 1
    });
    expect(full["principalRef"]).toMatch(/^member_[0-9a-f]{24}$/u);
    expect(full["clientRef"]).toMatch(/^client_[0-9a-f]{24}$/u);
    expect(lines[1]).not.toContain("person@example.com");
    expect(lines[1]).not.toContain("client-secret-name");
  });

  it("rejects weak keys, unsafe service codes and unknown fields", () => {
    const options = {
      pseudonymKey: Buffer.alloc(32, 0x52),
      service: "boardagent",
      clock: () => new Date("2026-09-01T00:00:00Z"),
      sink: () => undefined
    };
    expect(() => createStructuredLogger({ ...options, pseudonymKey: "short" })).toThrow(
      "at least 32 bytes"
    );
    expect(() => createStructuredLogger({ ...options, service: "unsafe service" })).toThrow();
    const logger = createStructuredLogger(options);
    expect(() =>
      logger.write({
        level: "info",
        event: "started",
        result: "success",
        rawEmail: "forbidden"
      } as never)
    ).toThrow();
  });
});
