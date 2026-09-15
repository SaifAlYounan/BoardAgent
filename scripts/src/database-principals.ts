import { createHash, createHmac, pbkdf2Sync, randomBytes } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import path from "node:path";

import { assertSecretDirectoryReady } from "@boardagent/config";
import type { Pool, PoolClient } from "pg";

const PROVISION_LOCK = 4_242_486_065_882_918n;
const PASSWORD_PATTERN = /^[A-Za-z0-9_-]{43,128}$/u;

export const DATABASE_PRINCIPALS = [
  {
    purpose: "migrator",
    loginRole: "boardagent_migrator_login",
    capabilityRole: "boardagent_migrator",
    replication: false,
    connectionLimit: 2
  },
  {
    purpose: "server",
    loginRole: "boardagent_server_login",
    capabilityRole: "boardagent_server",
    replication: false,
    connectionLimit: 40
  },
  {
    purpose: "worker",
    loginRole: "boardagent_worker_login",
    capabilityRole: "boardagent_worker",
    replication: false,
    connectionLimit: 24
  },
  {
    purpose: "backup",
    loginRole: "boardagent_backup_login",
    capabilityRole: "boardagent_backup",
    replication: true,
    connectionLimit: 4
  }
] as const;

export type DatabasePrincipalPurpose = (typeof DATABASE_PRINCIPALS)[number]["purpose"];

export type DatabasePrincipalPasswordFiles = Readonly<Record<DatabasePrincipalPurpose, string>>;

export interface DatabasePrincipalProvisionReceipt {
  readonly schemaVersion: "boardagent.database-principal-provision.v1";
  readonly database: string;
  readonly principals: readonly {
    readonly purpose: DatabasePrincipalPurpose;
    readonly loginRole: string;
    readonly capabilityRole: string;
    readonly replication: boolean;
  }[];
}

function sqlIdentifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}

export function postgresScramVerifier(
  password: Uint8Array,
  salt: Uint8Array = randomBytes(16)
): string {
  if (password.byteLength < 43 || password.byteLength > 128) {
    throw new Error("database role password has invalid length");
  }
  if (salt.byteLength !== 16) throw new Error("SCRAM salt must contain exactly 16 bytes");
  const salted = pbkdf2Sync(password, salt, 4_096, 32, "sha256");
  const clientKey = createHmac("sha256", salted).update("Client Key", "utf8").digest();
  const storedKey = createHash("sha256").update(clientKey).digest();
  const serverKey = createHmac("sha256", salted).update("Server Key", "utf8").digest();
  try {
    return `SCRAM-SHA-256$4096:${Buffer.from(salt).toString("base64")}$${storedKey.toString("base64")}:${serverKey.toString("base64")}`;
  } finally {
    salted.fill(0);
    clientKey.fill(0);
    storedKey.fill(0);
    serverKey.fill(0);
  }
}

async function passwordFile(filePath: string): Promise<Buffer> {
  assertSecretDirectoryReady(filePath);
  const resolved = path.resolve(filePath);
  const stat = await lstat(resolved);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error("database role password must be a regular file");
  }
  if ((stat.mode & 0o077) !== 0) {
    throw new Error("database role password file must be owner-only");
  }
  if (stat.size < 43 || stat.size > 129) {
    throw new Error("database role password file has invalid length");
  }
  const raw = await readFile(resolved);
  const value = raw.at(-1) === 0x0a ? Buffer.from(raw.subarray(0, -1)) : Buffer.from(raw);
  raw.fill(0);
  const text = new TextDecoder("utf-8", { fatal: true }).decode(value);
  if (!PASSWORD_PATTERN.test(text) || Buffer.byteLength(text, "utf8") !== value.length) {
    value.fill(0);
    throw new Error("database role password must be 43-128 canonical base64url characters");
  }
  return value;
}

async function assertProvisionAuthority(client: PoolClient): Promise<string> {
  const result = await client.query<{
    database_name: string;
    database_owner: boolean;
    role_create: boolean;
    role_super: boolean;
  }>(
    `select current_database() as database_name,
            database.datdba=(select oid from pg_roles where rolname=current_user) as database_owner,
            role.rolcreaterole as role_create,
            role.rolsuper as role_super
       from pg_database as database
       join pg_roles as role on role.rolname=current_user
      where database.datname=current_database()`
  );
  const authority = result.rows[0];
  if (
    !authority ||
    result.rows.length !== 1 ||
    !authority.database_owner ||
    (!authority.role_create && !authority.role_super)
  ) {
    throw new Error("database principal provisioning requires the database owner with CREATEROLE");
  }
  return authority.database_name;
}

async function assertCapabilityRoles(client: PoolClient): Promise<void> {
  const expected = DATABASE_PRINCIPALS.map(({ capabilityRole }) => capabilityRole);
  const result = await client.query<{
    rolbypassrls: boolean;
    rolcanlogin: boolean;
    rolcreatedb: boolean;
    rolcreaterole: boolean;
    rolinherit: boolean;
    rolname: string;
    rolreplication: boolean;
    rolsuper: boolean;
  }>(
    `select rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,
            rolreplication,rolbypassrls
       from pg_roles where rolname=any($1) order by rolname`,
    [expected]
  );
  if (
    result.rows.length !== expected.length ||
    result.rows.some(
      (role) =>
        role.rolsuper ||
        role.rolinherit ||
        role.rolcreaterole ||
        role.rolcreatedb ||
        role.rolcanlogin ||
        role.rolreplication ||
        role.rolbypassrls
    )
  ) {
    throw new Error("database capability roles are missing or unsafe");
  }
}

async function assertNoUnexpectedMemberships(client: PoolClient): Promise<void> {
  const loginRoles = DATABASE_PRINCIPALS.map(({ loginRole }) => loginRole);
  const memberships = await client.query<{ granted_role: string; login_role: string }>(
    `select granted.rolname as granted_role,member.rolname as login_role
       from pg_auth_members as membership
       join pg_roles as granted on granted.oid=membership.roleid
       join pg_roles as member on member.oid=membership.member
      where member.rolname=any($1)`,
    [loginRoles]
  );
  for (const membership of memberships.rows) {
    const expected = DATABASE_PRINCIPALS.find(
      ({ loginRole }) => loginRole === membership.login_role
    );
    if (!expected || expected.capabilityRole !== membership.granted_role) {
      throw new Error(
        `database login principal ${membership.login_role} has unexpected membership`
      );
    }
  }
}

async function provisionOne(
  client: PoolClient,
  principal: (typeof DATABASE_PRINCIPALS)[number],
  verifier: string
): Promise<void> {
  if (!/^SCRAM-SHA-256\$4096:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$/u.test(verifier)) {
    throw new Error("generated database verifier is malformed");
  }
  const login = sqlIdentifier(principal.loginRole);
  const capability = sqlIdentifier(principal.capabilityRole);
  const existing = await client.query<{
    rolbypassrls: boolean;
    rolcreatedb: boolean;
    rolcreaterole: boolean;
    rolname: string;
    rolsuper: boolean;
  }>(
    `select rolname,rolsuper,rolcreaterole,rolcreatedb,rolbypassrls
       from pg_roles where rolname=$1`,
    [principal.loginRole]
  );
  if (
    existing.rows.some(
      (role) => role.rolsuper || role.rolcreaterole || role.rolcreatedb || role.rolbypassrls
    )
  ) {
    throw new Error(`database login principal ${principal.loginRole} has unsafe attributes`);
  }
  if (existing.rows.length === 0) {
    await client.query(
      `create role ${login} login noinherit nosuperuser nocreatedb nocreaterole ${
        principal.replication ? "replication" : "noreplication"
      } nobypassrls connection limit ${String(principal.connectionLimit)}`
    );
  }
  await client.query(
    `alter role ${login} with login noinherit nosuperuser nocreatedb nocreaterole ${
      principal.replication ? "replication" : "noreplication"
    } nobypassrls connection limit ${String(principal.connectionLimit)} password '${verifier}' valid until 'infinity'`
  );
  await client.query(`revoke all on schema public from ${login}`);
  await client.query(`grant ${capability} to ${login}`);
}

export async function provisionDatabasePrincipals(
  pool: Pool,
  files: DatabasePrincipalPasswordFiles,
  entropy: (length: number) => Uint8Array = randomBytes
): Promise<DatabasePrincipalProvisionReceipt> {
  const paths = DATABASE_PRINCIPALS.map(({ purpose }) => path.resolve(files[purpose]));
  if (new Set(paths).size !== paths.length) {
    throw new Error("database role password files must be purpose-separated");
  }
  const passwords = await Promise.all(paths.map(passwordFile));
  try {
    const passwordFingerprints = passwords.map((value) =>
      createHash("sha256").update(value).digest("hex")
    );
    if (new Set(passwordFingerprints).size !== passwordFingerprints.length) {
      throw new Error("database role passwords must be purpose-separated");
    }
    const verifiers = passwords.map((password) => postgresScramVerifier(password, entropy(16)));
    const client = await pool.connect();
    try {
      await client.query("begin");
      await client.query("select pg_advisory_xact_lock($1)", [PROVISION_LOCK.toString()]);
      const database = await assertProvisionAuthority(client);
      await assertCapabilityRoles(client);
      await assertNoUnexpectedMemberships(client);
      for (const [index, principal] of DATABASE_PRINCIPALS.entries()) {
        await provisionOne(client, principal, verifiers[index]!);
      }
      await assertNoUnexpectedMemberships(client);
      const databaseIdentifier = sqlIdentifier(database);
      await client.query(`revoke connect on database ${databaseIdentifier} from public`);
      for (const { loginRole } of DATABASE_PRINCIPALS) {
        await client.query(
          `grant connect on database ${databaseIdentifier} to ${sqlIdentifier(loginRole)}`
        );
      }
      await client.query("commit");
      return {
        schemaVersion: "boardagent.database-principal-provision.v1",
        database,
        principals: DATABASE_PRINCIPALS.map(
          ({ purpose, loginRole, capabilityRole, replication }) => ({
            purpose,
            loginRole,
            capabilityRole,
            replication
          })
        )
      };
    } catch (error) {
      await client.query("rollback").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  } finally {
    passwords.forEach((password) => password.fill(0));
  }
}
