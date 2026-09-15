import { hkdfSync } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import path from "node:path";

import { z } from "zod";

const ALLOWED_KEYS = new Set([
  "BOARDAGENT_ENV",
  "BOARDAGENT_DATABASE_URL",
  "BOARDAGENT_DATABASE_PASSWORD_FILE",
  "BOARDAGENT_ORGANIZATION_ID",
  "BOARDAGENT_PUBLIC_BASE_URL",
  "BOARDAGENT_AUTHORIZATION_MODE",
  "BOARDAGENT_BLOB_ROOT",
  "BOARDAGENT_DEV_MASTER_SECRET",
  "BOARDAGENT_OAUTH_SIGNING_KEY_FILE",
  "BOARDAGENT_EVIDENCE_SIGNING_KEY_FILE",
  "BOARDAGENT_BROWSER_SESSION_KEY_FILE",
  "BOARDAGENT_DATA_KEK_FILE",
  "BOARDAGENT_RETAINED_DATA_KEYS_FILE",
  "BOARDAGENT_OIDC_ISSUER",
  "BOARDAGENT_OIDC_CLIENT_ID",
  "BOARDAGENT_OIDC_CLIENT_SECRET_FILE",
  "BOARDAGENT_CLIENT_ALLOWLIST",
  "BOARDAGENT_ACCESS_TOKEN_TTL_SECONDS",
  "BOARDAGENT_STAGE_TTL_SECONDS",
  "BOARDAGENT_TRUSTED_PROXY_HOPS",
  "BOARDAGENT_WEBHOOKS_ENABLED",
  "BOARDAGENT_EXPORT_MAX_BYTES",
  "BOARDAGENT_EXPORT_CHUNK_BYTES",
  "BOARDAGENT_LOG_LEVEL"
]);

const BaseSchema = z
  .object({
    BOARDAGENT_ENV: z.enum(["development", "test", "production"]),
    BOARDAGENT_DATABASE_URL: z.string().min(1),
    BOARDAGENT_DATABASE_PASSWORD_FILE: z.string().min(1).optional(),
    BOARDAGENT_ORGANIZATION_ID: z
      .string()
      .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u),
    BOARDAGENT_PUBLIC_BASE_URL: z.url(),
    BOARDAGENT_AUTHORIZATION_MODE: z.enum(["builtin", "oidc"]),
    BOARDAGENT_BLOB_ROOT: z.string().min(1),
    BOARDAGENT_DEV_MASTER_SECRET: z.string().min(32).max(4096).optional(),
    BOARDAGENT_OAUTH_SIGNING_KEY_FILE: z.string().min(1).optional(),
    BOARDAGENT_EVIDENCE_SIGNING_KEY_FILE: z.string().min(1).optional(),
    BOARDAGENT_BROWSER_SESSION_KEY_FILE: z.string().min(1).optional(),
    BOARDAGENT_DATA_KEK_FILE: z.string().min(1).optional(),
    BOARDAGENT_RETAINED_DATA_KEYS_FILE: z.string().min(1).max(4096).optional(),
    BOARDAGENT_OIDC_ISSUER: z.url().optional(),
    BOARDAGENT_OIDC_CLIENT_ID: z.string().min(1).optional(),
    BOARDAGENT_OIDC_CLIENT_SECRET_FILE: z.string().min(1).optional(),
    BOARDAGENT_CLIENT_ALLOWLIST: z.string().optional(),
    // Issued JWTs and persisted consent use these exact frozen lifetimes. Refuse
    // settings the runtime cannot honor instead of silently accepting another policy.
    BOARDAGENT_ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().pipe(z.literal(900)).default(900),
    BOARDAGENT_STAGE_TTL_SECONDS: z.coerce.number().pipe(z.literal(600)).default(600),
    BOARDAGENT_TRUSTED_PROXY_HOPS: z.coerce.number().int().min(0).max(4).default(1),
    BOARDAGENT_WEBHOOKS_ENABLED: z.enum(["true", "false"]).default("false"),
    BOARDAGENT_EXPORT_MAX_BYTES: z.coerce
      .number()
      .int()
      .min(1_048_576)
      .max(1_073_741_824)
      .default(268_435_456),
    BOARDAGENT_EXPORT_CHUNK_BYTES: z.coerce
      .number()
      .int()
      .min(65_536)
      .max(10_485_760)
      .default(4_194_304),
    BOARDAGENT_LOG_LEVEL: z.enum(["error", "warn", "info"]).default("info")
  })
  .strict();

export interface PurposeKeys {
  readonly oauth: Uint8Array | string;
  readonly evidence: Uint8Array | string;
  readonly browserSession: Uint8Array | string;
  readonly dataEncryption: Uint8Array | string;
}

export interface BoardAgentConfig {
  readonly environment: "development" | "test" | "production";
  readonly databaseUrl: string;
  readonly organizationId: string;
  readonly publicBaseUrl: URL;
  readonly canonicalResourceUri: string;
  readonly authorizationMode: "builtin" | "oidc";
  readonly blobRoot: string;
  readonly keySources: PurposeKeys;
  readonly retainedDataKeysFile?: string;
  readonly oidc: null | {
    readonly issuer: string;
    readonly clientId: string;
    readonly clientSecretFile: string;
  };
  readonly clientAllowlist: ReadonlySet<string> | null;
  readonly accessTokenTtlSeconds: number;
  readonly stageTtlSeconds: number;
  readonly trustedProxyHops: number;
  readonly webhooksEnabled: boolean;
  readonly exportMaximumBytes: number;
  readonly exportChunkBytes: number;
  readonly logLevel: "error" | "warn" | "info";
}

export interface ParseConfigOptions {
  /** Unit-test seam. Production uses the fail-closed regular-file reader below. */
  readonly readDatabasePasswordFile?: (filePath: string) => string;
}

interface DatabaseUrlEnvironment {
  readonly BOARDAGENT_ENV?: string | undefined;
  readonly BOARDAGENT_DATABASE_URL?: string | undefined;
  readonly BOARDAGENT_DATABASE_PASSWORD_FILE?: string | undefined;
}

export type ProductionDatabasePurpose = "migrator" | "server" | "worker" | "backup";

function derive(masterSecret: string, purpose: string): Uint8Array {
  return new Uint8Array(
    hkdfSync("sha256", Buffer.from(masterSecret), Buffer.from("boardagent.dev.v1"), purpose, 32)
  );
}

function normalizeBaseUrl(value: string, production: boolean): URL {
  const url = new URL(value);
  if (url.username || url.password || url.search || url.hash)
    throw new Error("public base URL cannot carry credentials/query/fragment");
  if (url.pathname !== "/" && url.pathname !== "")
    throw new Error("public base URL must not contain a path");
  if (production && url.protocol !== "https:")
    throw new Error("production public base URL must use HTTPS");
  if (url.protocol !== "http:" && url.protocol !== "https:")
    throw new Error("public base URL must use HTTP or HTTPS");
  if (
    !production &&
    url.protocol === "http:" &&
    !["127.0.0.1", "localhost", "[::1]", "::1"].includes(url.hostname)
  ) {
    throw new Error("development HTTP public base URL must be loopback");
  }
  url.pathname = "/";
  return url;
}

/** An interrupted provisioning run must not activate a partially replaced secret set. */
export function assertSecretDirectoryReady(filePath: string): void {
  try {
    lstatSync(path.join(path.dirname(filePath), ".initialization-incomplete"));
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return;
    throw error;
  }
  throw new Error("secret initialization incomplete; finish provisioning before startup");
}

function readDatabasePasswordFile(filePath: string): string {
  assertSecretDirectoryReady(filePath);
  const stat = lstatSync(filePath);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error("production database password must be a regular file");
  }
  if ((stat.mode & 0o077) !== 0) {
    throw new Error("production database password file must be owner-only");
  }
  if (stat.size < 32 || stat.size > 4_097) {
    throw new Error("production database password file has invalid length");
  }
  const raw = new TextDecoder("utf-8", { fatal: true }).decode(readFileSync(filePath));
  return raw.endsWith("\n") ? raw.slice(0, -1) : raw;
}

function productionDatabaseCredential(
  value: string,
  passwordFile: string | undefined,
  readPassword: (filePath: string) => string
): string {
  const url = new URL(value);
  if (url.protocol !== "postgresql:" && url.protocol !== "postgres:") {
    throw new Error("production database URL must use PostgreSQL");
  }
  if (!url.username) {
    throw new Error("production database URL requires an explicit principal");
  }
  if (url.password) {
    throw new Error("production database password must come from its secret file");
  }
  if (!passwordFile) {
    throw new Error("production requires BOARDAGENT_DATABASE_PASSWORD_FILE");
  }
  const password = readPassword(passwordFile);
  if (
    password.length < 32 ||
    password.length > 4_096 ||
    password.includes("\0") ||
    password.includes("\r") ||
    password.includes("\n")
  ) {
    throw new Error("production database password file has invalid content");
  }
  const normalizedPassword = password.toLowerCase();
  if (
    ["boardagent-local-only", "boardagent", "postgres", "password", "replace-me"].includes(
      normalizedPassword
    ) ||
    /(?:change[-_ ]?me|replace[-_ ]?me|default[-_ ]?secret)/iu.test(password)
  ) {
    throw new Error("production database password must override the local credential");
  }
  url.password = password;
  return url.toString();
}

export function resolveDatabaseUrl(
  env: DatabaseUrlEnvironment,
  options: ParseConfigOptions = {}
): string {
  const environment = z.enum(["development", "test", "production"]).parse(env.BOARDAGENT_ENV);
  const databaseUrl = z.string().min(1).parse(env.BOARDAGENT_DATABASE_URL);
  if (environment !== "production") {
    if (env.BOARDAGENT_DATABASE_PASSWORD_FILE) {
      throw new Error("database password files are production-only");
    }
    return databaseUrl;
  }
  return productionDatabaseCredential(
    databaseUrl,
    env.BOARDAGENT_DATABASE_PASSWORD_FILE,
    options.readDatabasePasswordFile ?? readDatabasePasswordFile
  );
}

function productionKeySources(parsed: z.infer<typeof BaseSchema>): PurposeKeys {
  const entries = [
    parsed.BOARDAGENT_DATABASE_PASSWORD_FILE,
    parsed.BOARDAGENT_OAUTH_SIGNING_KEY_FILE,
    parsed.BOARDAGENT_EVIDENCE_SIGNING_KEY_FILE,
    parsed.BOARDAGENT_BROWSER_SESSION_KEY_FILE,
    parsed.BOARDAGENT_DATA_KEK_FILE
  ];
  if (entries.some((entry) => entry === undefined) || new Set(entries).size !== 5) {
    throw new Error("production requires distinct database and purpose-separated key files");
  }
  return {
    oauth: parsed.BOARDAGENT_OAUTH_SIGNING_KEY_FILE as string,
    evidence: parsed.BOARDAGENT_EVIDENCE_SIGNING_KEY_FILE as string,
    browserSession: parsed.BOARDAGENT_BROWSER_SESSION_KEY_FILE as string,
    dataEncryption: parsed.BOARDAGENT_DATA_KEK_FILE as string
  };
}

function devKeySources(parsed: z.infer<typeof BaseSchema>): PurposeKeys {
  if (!parsed.BOARDAGENT_DEV_MASTER_SECRET)
    throw new Error("local profile requires BOARDAGENT_DEV_MASTER_SECRET");
  if (
    /(?:change[-_ ]?me|replace[-_ ]?me|default[-_ ]?secret|boardagent[-_ ]?local[-_ ]?only)/iu.test(
      parsed.BOARDAGENT_DEV_MASTER_SECRET
    )
  ) {
    throw new Error("development master secret cannot be a placeholder");
  }
  return {
    oauth: derive(parsed.BOARDAGENT_DEV_MASTER_SECRET, "oauth-token-signing"),
    evidence: derive(parsed.BOARDAGENT_DEV_MASTER_SECRET, "evidence-signing"),
    browserSession: derive(parsed.BOARDAGENT_DEV_MASTER_SECRET, "browser-session"),
    dataEncryption: derive(parsed.BOARDAGENT_DEV_MASTER_SECRET, "data-encryption")
  };
}

export function parseConfig(
  env: NodeJS.ProcessEnv,
  options: ParseConfigOptions = {}
): BoardAgentConfig {
  const boardAgentEntries = Object.entries(env).filter(
    ([key, value]) => key.startsWith("BOARDAGENT_") && value !== undefined
  );
  const unknown = boardAgentEntries.map(([key]) => key).filter((key) => !ALLOWED_KEYS.has(key));
  if (unknown.length > 0)
    throw new Error(`unknown BoardAgent configuration: ${unknown.toSorted().join(", ")}`);
  const parsed = BaseSchema.parse(Object.fromEntries(boardAgentEntries));
  const production = parsed.BOARDAGENT_ENV === "production";
  const baseUrl = normalizeBaseUrl(parsed.BOARDAGENT_PUBLIC_BASE_URL, production);
  if (production && parsed.BOARDAGENT_DEV_MASTER_SECRET)
    throw new Error("development master secret is forbidden in production");
  const databaseUrl = resolveDatabaseUrl(parsed, options);
  const retainedDataKeysFile = parsed.BOARDAGENT_RETAINED_DATA_KEYS_FILE;
  if (retainedDataKeysFile !== undefined) {
    if (!production) throw new Error("retained data-key files are production-only");
    if (
      !path.isAbsolute(retainedDataKeysFile) ||
      path.normalize(retainedDataKeysFile) !== retainedDataKeysFile ||
      retainedDataKeysFile.includes("\0") ||
      [
        parsed.BOARDAGENT_DATABASE_PASSWORD_FILE,
        parsed.BOARDAGENT_OAUTH_SIGNING_KEY_FILE,
        parsed.BOARDAGENT_EVIDENCE_SIGNING_KEY_FILE,
        parsed.BOARDAGENT_BROWSER_SESSION_KEY_FILE,
        parsed.BOARDAGENT_DATA_KEK_FILE
      ].some((file) => file !== undefined && path.resolve(file) === retainedDataKeysFile)
    )
      throw new Error("retained data-key manifest requires a distinct absolute file path");
  }

  let oidc: BoardAgentConfig["oidc"] = null;
  if (parsed.BOARDAGENT_AUTHORIZATION_MODE === "oidc") {
    if (
      !parsed.BOARDAGENT_OIDC_ISSUER ||
      !parsed.BOARDAGENT_OIDC_CLIENT_ID ||
      !parsed.BOARDAGENT_OIDC_CLIENT_SECRET_FILE
    ) {
      throw new Error("OIDC mode requires issuer, client ID, and client secret file");
    }
    oidc = {
      issuer: parsed.BOARDAGENT_OIDC_ISSUER,
      clientId: parsed.BOARDAGENT_OIDC_CLIENT_ID,
      clientSecretFile: parsed.BOARDAGENT_OIDC_CLIENT_SECRET_FILE
    };
  }

  const allowlist = parsed.BOARDAGENT_CLIENT_ALLOWLIST
    ? new Set(
        parsed.BOARDAGENT_CLIENT_ALLOWLIST.split(",")
          .map((value) => value.trim())
          .filter(Boolean)
      )
    : null;

  return {
    environment: parsed.BOARDAGENT_ENV,
    databaseUrl,
    organizationId: parsed.BOARDAGENT_ORGANIZATION_ID,
    publicBaseUrl: baseUrl,
    canonicalResourceUri: new URL("mcp", baseUrl).toString().replace(/\/$/u, ""),
    authorizationMode: parsed.BOARDAGENT_AUTHORIZATION_MODE,
    blobRoot: parsed.BOARDAGENT_BLOB_ROOT,
    keySources: production ? productionKeySources(parsed) : devKeySources(parsed),
    ...(retainedDataKeysFile === undefined ? {} : { retainedDataKeysFile }),
    oidc,
    clientAllowlist: allowlist,
    accessTokenTtlSeconds: parsed.BOARDAGENT_ACCESS_TOKEN_TTL_SECONDS,
    stageTtlSeconds: parsed.BOARDAGENT_STAGE_TTL_SECONDS,
    trustedProxyHops: parsed.BOARDAGENT_TRUSTED_PROXY_HOPS,
    webhooksEnabled: parsed.BOARDAGENT_WEBHOOKS_ENABLED === "true",
    exportMaximumBytes: parsed.BOARDAGENT_EXPORT_MAX_BYTES,
    exportChunkBytes: parsed.BOARDAGENT_EXPORT_CHUNK_BYTES,
    logLevel: parsed.BOARDAGENT_LOG_LEVEL
  };
}

export function assertProductionDatabasePurpose(
  config: BoardAgentConfig,
  purpose: ProductionDatabasePurpose
): void {
  if (config.environment !== "production") return;
  const actual = decodeURIComponent(new URL(config.databaseUrl).username);
  const expected = `boardagent_${purpose}_login`;
  if (actual !== expected) {
    throw new Error(`production ${purpose} process requires database principal ${expected}`);
  }
}
