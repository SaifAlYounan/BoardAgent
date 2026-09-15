import { guardRuntimeDatabaseTransaction } from "./runtime-lease.js";
import { randomInt } from "node:crypto";

import type { Pool, PoolClient } from "pg";

import { canonicalSha256, UuidV7Schema } from "@boardagent/contracts";

export interface RequestDatabaseContext {
  readonly organizationId: string;
  readonly memberId: string;
  readonly clientId: string;
  readonly tokenJti: string;
  readonly boardIds: readonly string[];
}

export interface TransactionOptions {
  readonly isolation?: "read committed" | "repeatable read" | "serializable";
  readonly lockTimeoutMs?: number;
  readonly statementTimeoutMs?: number;
  /**
   * Replay a non-serializable transaction after a serialization failure or deadlock
   * (`40001`, `40P01`), with the same bounded jittered schedule serializable
   * transactions use. Only for database-only callbacks that may run again from the
   * beginning, such as an audit append with a caller-owned event id.
   */
  readonly retryConflicts?: boolean;
  /** Test/bootstrap seam only. Production pools connect as their already-scoped role. */
  readonly assumeRole?: "boardagent_server" | "boardagent_worker";
}

export interface WorkerTransactionOptions {
  readonly isolation?: "read committed" | "repeatable read" | "serializable";
  readonly lockTimeoutMs?: number;
  readonly statementTimeoutMs?: number;
  /** Test/bootstrap seam only. Production worker pools connect as this role directly. */
  readonly assumeRole?: "boardagent_worker";
}

export interface BackupTransactionOptions {
  readonly lockTimeoutMs?: number;
  readonly statementTimeoutMs?: number;
  /** Test/bootstrap seam only. Production backup pools connect as this role directly. */
  readonly assumeRole?: "boardagent_backup";
}

export interface BootstrapTransactionOptions {
  /** Inventory commands can require PostgreSQL to refuse every write. */
  readonly readOnly?: boolean;
  readonly lockTimeoutMs?: number;
  readonly statementTimeoutMs?: number;
  /** Test/bootstrap seam only. Production bootstrap uses the migrator connection. */
  readonly assumeRole?: "boardagent_migrator";
}

export interface IdentityDatabaseContext {
  readonly organizationId: string;
  readonly boardIds?: readonly string[];
}

export interface IdentityTransactionOptions {
  /** Serializable remains the identity default; atomic contention counters may opt into read committed. */
  readonly isolation?: "read committed" | "serializable";
  /** Public verification metadata can require PostgreSQL to refuse every write. */
  readonly readOnly?: boolean;
  readonly lockTimeoutMs?: number;
  readonly statementTimeoutMs?: number;
  /** Test/bootstrap seam only. Production identity pools connect as this role directly. */
  readonly assumeRole?: "boardagent_server";
}

function boundedMilliseconds(value: number | undefined, fallback: number): number {
  const selected = value ?? fallback;
  if (!Number.isSafeInteger(selected) || selected < 1 || selected > 60_000) {
    throw new RangeError("database timeout must be an integer from 1 through 60000 milliseconds");
  }
  return selected;
}

export function normalizeRequestDatabaseContext(
  context: RequestDatabaseContext
): RequestDatabaseContext & { readonly contextSha256: string } {
  const organizationId = UuidV7Schema.parse(context.organizationId);
  const memberId = UuidV7Schema.parse(context.memberId);
  const clientId = UuidV7Schema.parse(context.clientId);
  const tokenJti = UuidV7Schema.parse(context.tokenJti);
  const boardIds = [
    ...new Set(context.boardIds.map((boardId) => UuidV7Schema.parse(boardId)))
  ].toSorted();
  if (boardIds.length > 25)
    throw new RangeError("request context exceeds the 25-board deployment limit");
  const normalized = { organizationId, memberId, clientId, tokenJti, boardIds };
  return { ...normalized, contextSha256: canonicalSha256(normalized) };
}

async function installLocalContext(
  client: PoolClient,
  context: ReturnType<typeof normalizeRequestDatabaseContext>
): Promise<void> {
  await client.query(
    `select set_config('boardagent.organization_id',$1,true),
            set_config('boardagent.member_id',$2,true),
            set_config('boardagent.client_id',$3,true),
            set_config('boardagent.token_jti',$4,true),
            set_config('boardagent.board_ids',$5,true),
            set_config('boardagent.context_sha256',$6,true),
            set_config('boardagent.transaction_scope','request',true)`,
    [
      context.organizationId,
      context.memberId,
      context.clientId,
      context.tokenJti,
      JSON.stringify(context.boardIds),
      context.contextSha256
    ]
  );
}

// A supported 100-request burst may produce more than twelve conflicting snapshots
// at the single audit head. Replay remains finite, database-only, and fully authorized;
// caller-owned idempotency keys survive every attempt. Latency gates include all retries.
const SERIALIZABLE_ATTEMPT_LIMIT = 100;
const SERIALIZABLE_RETRY_BASE_MILLISECONDS = 4;
const SERIALIZABLE_RETRY_MAX_MILLISECONDS = 250;

function retryableTransactionError(error: unknown): boolean {
  if (typeof error !== "object" || error === null || !("code" in error)) return false;
  return error.code === "40001" || error.code === "40P01";
}

async function waitBeforeSerializableRetry(failedAttempt: number): Promise<void> {
  const ceiling = Math.min(
    SERIALIZABLE_RETRY_MAX_MILLISECONDS,
    SERIALIZABLE_RETRY_BASE_MILLISECONDS * 2 ** Math.max(0, failedAttempt - 1)
  );
  // Full jitter prevents identical requests from re-forming the same conflict wave while
  // keeping total retry time bounded. Transaction callbacks remain database-only and replay
  // from the beginning with the same caller-owned idempotency key.
  const milliseconds = randomInt(1, ceiling + 1);
  await new Promise<void>((resolve) => setTimeout(resolve, milliseconds));
}

/** A leased connection may fail between queries as well as during one. */
function guardTransactionConnection(client: PoolClient) {
  let connectionError: Error | undefined;
  const observeError = (error: Error) => {
    connectionError ??= error;
  };
  client.on("error", observeError);
  return {
    assertAvailable: () => {
      if (connectionError) throw connectionError;
    },
    rollback: async (open: boolean): Promise<boolean> => {
      // Return whether destruction is required; never return an unrolled-back
      // transaction or a terminated connection to the pool.
      if (!open || connectionError) return true;
      try {
        await client.query("rollback");
        return false;
      } catch {
        return true;
      }
    },
    release: (destroy = false) => {
      try {
        client.release(destroy || connectionError !== undefined);
      } finally {
        client.removeListener("error", observeError);
      }
    }
  };
}

async function runRequestTransactionAttempt<T>(
  pool: Pool,
  context: ReturnType<typeof normalizeRequestDatabaseContext>,
  run: (client: PoolClient) => Promise<T>,
  options: TransactionOptions,
  isolation: NonNullable<TransactionOptions["isolation"]>,
  lockTimeoutMs: number,
  statementTimeoutMs: number
): Promise<T> {
  const client = await pool.connect();
  const connection = guardTransactionConnection(client);
  let open = false;
  let destroy = false;
  try {
    await client.query("begin");
    open = true;
    await client.query(`set local transaction isolation level ${isolation}`);
    await client.query("select set_config('lock_timeout',$1,true)", [`${String(lockTimeoutMs)}ms`]);
    await client.query("select set_config('statement_timeout',$1,true)", [
      `${String(statementTimeoutMs)}ms`
    ]);
    if (options.assumeRole) await client.query(`set local role ${options.assumeRole}`);
    await guardRuntimeDatabaseTransaction(client);
    await installLocalContext(client, context);
    const result = await run(client);
    connection.assertAvailable();
    await client.query("commit");
    open = false;
    return result;
  } catch (error) {
    destroy = await connection.rollback(open);
    throw error;
  } finally {
    connection.release(destroy);
  }
}

export async function withRequestTransaction<T>(
  pool: Pool,
  rawContext: RequestDatabaseContext,
  run: (client: PoolClient) => Promise<T>,
  options: TransactionOptions = {}
): Promise<T> {
  const context = normalizeRequestDatabaseContext(rawContext);
  const isolation = options.isolation ?? "read committed";
  const lockTimeoutMs = boundedMilliseconds(options.lockTimeoutMs, 10_000);
  const statementTimeoutMs = boundedMilliseconds(options.statementTimeoutMs, 30_000);
  const attemptLimit =
    isolation === "serializable" || options.retryConflicts === true
      ? SERIALIZABLE_ATTEMPT_LIMIT
      : 1;
  for (let attempt = 1; attempt <= attemptLimit; attempt += 1) {
    try {
      return await runRequestTransactionAttempt(
        pool,
        context,
        run,
        options,
        isolation,
        lockTimeoutMs,
        statementTimeoutMs
      );
    } catch (error) {
      if (attempt === attemptLimit || !retryableTransactionError(error)) throw error;
      await waitBeforeSerializableRetry(attempt);
    }
  }
  throw new Error("serializable request transaction exhausted without a result");
}

export async function withWorkerTransaction<T>(
  pool: Pool,
  run: (client: PoolClient) => Promise<T>,
  options: WorkerTransactionOptions = {}
): Promise<T> {
  const isolation = options.isolation ?? "read committed";
  const lockTimeoutMs = boundedMilliseconds(options.lockTimeoutMs, 10_000);
  const statementTimeoutMs = boundedMilliseconds(options.statementTimeoutMs, 30_000);
  const client = await pool.connect();
  const connection = guardTransactionConnection(client);
  let open = false;
  let destroy = false;
  try {
    await client.query("begin");
    open = true;
    await client.query(`set local transaction isolation level ${isolation}`);
    await client.query("select set_config('lock_timeout',$1,true)", [`${String(lockTimeoutMs)}ms`]);
    await client.query("select set_config('statement_timeout',$1,true)", [
      `${String(statementTimeoutMs)}ms`
    ]);
    if (options.assumeRole) await client.query(`set local role ${options.assumeRole}`);
    await guardRuntimeDatabaseTransaction(client);
    await client.query("select set_config('boardagent.transaction_scope','worker',true)");
    const result = await run(client);
    connection.assertAvailable();
    await client.query("commit");
    open = false;
    return result;
  } catch (error) {
    destroy = await connection.rollback(open);
    throw error;
  } finally {
    connection.release(destroy);
  }
}

async function withReadOnlyOperatorTransaction<T>(
  pool: Pool,
  scope: "backup" | "restore",
  run: (client: PoolClient) => Promise<T>,
  options: BackupTransactionOptions
): Promise<T> {
  const lockTimeoutMs = boundedMilliseconds(options.lockTimeoutMs, 10_000);
  const statementTimeoutMs = boundedMilliseconds(options.statementTimeoutMs, 60_000);
  const client = await pool.connect();
  const connection = guardTransactionConnection(client);
  let open = false;
  let destroy = false;
  try {
    await client.query("begin isolation level repeatable read read only");
    open = true;
    await client.query("select set_config('lock_timeout',$1,true)", [`${String(lockTimeoutMs)}ms`]);
    await client.query("select set_config('statement_timeout',$1,true)", [
      `${String(statementTimeoutMs)}ms`
    ]);
    if (options.assumeRole) await client.query(`set local role ${options.assumeRole}`);
    await guardRuntimeDatabaseTransaction(client);
    await client.query("select set_config('boardagent.transaction_scope',$1,true)", [scope]);
    const result = await run(client);
    connection.assertAvailable();
    await client.query("commit");
    open = false;
    return result;
  } catch (error) {
    destroy = await connection.rollback(open);
    throw error;
  } finally {
    connection.release(destroy);
  }
}

/**
 * Hold the repeatable-read, read-only snapshot open for the entire callback. A backup
 * driver may pass the exported snapshot identifier to pg_dump before the callback
 * returns; committing earlier would invalidate that boundary.
 */
export async function withBackupTransaction<T>(
  pool: Pool,
  run: (client: PoolClient) => Promise<T>,
  options: BackupTransactionOptions = {}
): Promise<T> {
  return withReadOnlyOperatorTransaction(pool, "backup", run, options);
}

/** Restore verification is always isolated, repeatable-read and physically read-only. */
export async function withRestoreTransaction<T>(
  pool: Pool,
  run: (client: PoolClient) => Promise<T>,
  options: BackupTransactionOptions = {}
): Promise<T> {
  return withReadOnlyOperatorTransaction(pool, "restore", run, options);
}

async function withScopedTransaction<T>(
  pool: Pool,
  scope: "bootstrap" | "identity",
  context: IdentityDatabaseContext | undefined,
  run: (client: PoolClient) => Promise<T>,
  options: BootstrapTransactionOptions | IdentityTransactionOptions
): Promise<T> {
  const isolation =
    scope === "identity" && "isolation" in options
      ? (options.isolation ?? "serializable")
      : "serializable";
  const lockTimeoutMs = boundedMilliseconds(options.lockTimeoutMs, 10_000);
  const statementTimeoutMs = boundedMilliseconds(options.statementTimeoutMs, 30_000);
  const attemptLimit = isolation === "serializable" ? SERIALIZABLE_ATTEMPT_LIMIT : 1;
  for (let attempt = 1; attempt <= attemptLimit; attempt += 1) {
    const client = await pool.connect();
    const connection = guardTransactionConnection(client);
    let open = false;
    try {
      await client.query(
        `begin isolation level ${isolation}${"readOnly" in options && options.readOnly === true ? " read only" : ""}`
      );
      open = true;
      await client.query("select set_config('lock_timeout',$1,true)", [
        `${String(lockTimeoutMs)}ms`
      ]);
      await client.query("select set_config('statement_timeout',$1,true)", [
        `${String(statementTimeoutMs)}ms`
      ]);
      if (options.assumeRole) await client.query(`set local role ${options.assumeRole}`);
      await guardRuntimeDatabaseTransaction(client);
      await client.query("select set_config('boardagent.transaction_scope',$1,true)", [scope]);
      if (context) {
        const organizationId = UuidV7Schema.parse(context.organizationId);
        const boardIds = [
          ...new Set((context.boardIds ?? []).map((boardId) => UuidV7Schema.parse(boardId)))
        ].toSorted();
        if (boardIds.length > 25) {
          throw new RangeError("identity context exceeds the 25-board deployment limit");
        }
        await client.query(
          `select set_config('boardagent.organization_id',$1,true),
                  set_config('boardagent.board_ids',$2,true)`,
          [organizationId, JSON.stringify(boardIds)]
        );
      }
      const result = await run(client);
      connection.assertAvailable();
      await client.query("commit");
      open = false;
      connection.release();
      return result;
    } catch (error) {
      const destroy = await connection.rollback(open);
      connection.release(destroy);
      if (attempt === attemptLimit || !retryableTransactionError(error)) throw error;
      await waitBeforeSerializableRetry(attempt);
    }
  }
  throw new Error(`${scope} transaction exhausted without a result`);
}

/** The sole pre-identity mutation scope. Its repository takes a singleton xact lock. */
export async function withBootstrapTransaction<T>(
  pool: Pool,
  run: (client: PoolClient) => Promise<T>,
  options: BootstrapTransactionOptions = {}
): Promise<T> {
  return withScopedTransaction(pool, "bootstrap", undefined, run, options);
}

/** Browser/OAuth identity state, isolated from authenticated MCP request context. */
export async function withIdentityTransaction<T>(
  pool: Pool,
  context: IdentityDatabaseContext,
  run: (client: PoolClient) => Promise<T>,
  options: IdentityTransactionOptions = {}
): Promise<T> {
  return withScopedTransaction(pool, "identity", context, run, options);
}
