import { randomUUID } from "node:crypto";

import { canonicalSha256, type JsonValue } from "@boardagent/contracts";
import {
  TYPED_JOB_TYPES,
  claimTypedJobInTransaction,
  completeTypedJobInTransaction,
  heartbeatJobLeaseInTransaction,
  withWorkerTransaction,
  withRuntimeDatabaseLease,
  type RuntimeDatabaseLease,
  type ClaimedJob,
  type TypedJobEnvelope
} from "@boardagent/db";
import type { Pool } from "pg";
import { z } from "zod";

const WorkerIdSchema = z.string().regex(/^[A-Za-z0-9._:-]{1,128}$/u);
const ErrorClassSchema = z.string().regex(/^[a-z][a-z0-9_.-]{1,127}$/u);

export type TypedJobType = TypedJobEnvelope["jobType"];

export interface TypedJobExecutionContext {
  readonly job: ClaimedJob;
  readonly signal: AbortSignal;
}

export type TypedJobHandler = (context: TypedJobExecutionContext) => Promise<JsonValue>;

/** Merges independently owned handlers without permitting shadowing or registry drift. */
export function composeTypedJobHandlers(
  ...groups: readonly ReadonlyMap<TypedJobType, TypedJobHandler>[]
): ReadonlyMap<TypedJobType, TypedJobHandler> {
  const collected = new Map<TypedJobType, TypedJobHandler>();
  const allowed = new Set<string>(TYPED_JOB_TYPES);
  for (const group of groups) {
    for (const [jobType, handler] of group) {
      if (!allowed.has(jobType)) throw new Error(`unknown worker handler: ${jobType}`);
      if (collected.has(jobType)) throw new Error(`duplicate worker handler: ${jobType}`);
      collected.set(jobType, handler);
    }
  }
  return new Map(
    TYPED_JOB_TYPES.flatMap((jobType) => {
      const handler = collected.get(jobType);
      return handler ? ([[jobType, handler]] as const) : [];
    })
  );
}

export class TypedJobExecutionError extends Error {
  public readonly errorClass: string;

  public constructor(
    errorClass: string,
    public readonly permanent: boolean,
    message = errorClass
  ) {
    super(message);
    this.name = "TypedJobExecutionError";
    this.errorClass = ErrorClassSchema.parse(errorClass);
  }
}

export type WorkerRunResult =
  | { readonly status: "idle" }
  | { readonly status: "rejected_invalid_job"; readonly jobId: string }
  | {
      readonly status: "succeeded" | "retry_scheduled" | "dead" | "lease_lost";
      readonly jobId: string;
      readonly jobType: TypedJobType;
      readonly attempt: number;
      readonly errorClass?: string;
    };

export interface BoardAgentTypedWorkerOptions {
  readonly runtimeDatabaseLease?: RuntimeDatabaseLease;
  /** Production schedules database-derived work before claiming; failures stop the loop. */
  readonly beforeClaim?: () => Promise<void>;
  /** Called only after a successful DB claim or live lease renewal. */
  readonly onProgress?: () => void;
  readonly handlers: ReadonlyMap<TypedJobType, TypedJobHandler>;
  readonly workerId?: string;
  readonly leaseSeconds?: number;
  readonly heartbeatMilliseconds?: number;
  readonly pollMilliseconds?: number;
  /** Test/local-owner seam only. Production connects as boardagent_worker directly. */
  readonly assumeRole?: "boardagent_worker";
}

function boundedInteger(value: number, label: string, minimum: number, maximum: number): number {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new RangeError(
      `${label} must be an integer from ${String(minimum)} through ${String(maximum)}`
    );
  }
  return value;
}

function wait(milliseconds: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return Promise.resolve();
  return new Promise((resolve) => {
    const timer = setTimeout(done, milliseconds);
    function done(): void {
      clearTimeout(timer);
      signal.removeEventListener("abort", done);
      resolve();
    }
    signal.addEventListener("abort", done, { once: true });
  });
}

function safeFailure(error: unknown): { readonly permanent: boolean; readonly errorClass: string } {
  if (error instanceof TypedJobExecutionError) {
    return { permanent: error.permanent, errorClass: error.errorClass };
  }
  return { permanent: false, errorClass: "unhandled_job_failure" };
}

function completionDigest(input: {
  readonly job: ClaimedJob;
  readonly result: "succeeded" | "retryable_failure" | "permanent_failure";
  readonly errorClass: string | null;
  readonly output: JsonValue | null;
}): string {
  return canonicalSha256({
    schemaVersion: "boardagent.worker-result.v1",
    jobId: input.job.jobId,
    jobType: input.job.envelope.jobType,
    attempt: input.job.attempt,
    inputPayloadSha256: input.job.payloadSha256,
    result: input.result,
    errorClass: input.errorClass,
    output: input.output
  });
}

/**
 * Crash-safe typed worker coordinator. Claims and completions are short database
 * transactions; handler I/O occurs outside them while a separate lease heartbeat runs.
 */
export class BoardAgentTypedWorker {
  private readonly handlers: ReadonlyMap<TypedJobType, TypedJobHandler>;
  private readonly workerId: string;
  private readonly leaseSeconds: number;
  private readonly heartbeatMilliseconds: number;
  private readonly pollMilliseconds: number;
  private readonly assumeRole: "boardagent_worker" | undefined;
  private readonly onProgress: (() => void) | undefined;
  private readonly runtimeDatabaseLease: RuntimeDatabaseLease | undefined;
  private draining = false;
  private readonly activeRuns = new Set<Promise<WorkerRunResult>>();
  private readonly beforeClaim: (() => Promise<void>) | undefined;

  public constructor(
    private readonly pool: Pool,
    options: BoardAgentTypedWorkerOptions
  ) {
    this.handlers = options.handlers;
    this.workerId = WorkerIdSchema.parse(
      options.workerId ?? `worker-${randomUUID().replaceAll("-", "")}`
    );
    this.leaseSeconds = boundedInteger(options.leaseSeconds ?? 30, "worker lease", 5, 300);
    this.heartbeatMilliseconds = boundedInteger(
      options.heartbeatMilliseconds ?? Math.max(1_000, Math.floor((this.leaseSeconds * 1_000) / 3)),
      "worker heartbeat interval",
      250,
      Math.max(250, this.leaseSeconds * 500)
    );
    this.pollMilliseconds = boundedInteger(
      options.pollMilliseconds ?? 1_000,
      "worker poll interval",
      25,
      60_000
    );
    this.assumeRole = options.assumeRole;
    this.onProgress = options.onProgress;
    this.beforeClaim = options.beforeClaim;
    this.runtimeDatabaseLease = options.runtimeDatabaseLease;
  }

  private transaction<T>(run: Parameters<typeof withWorkerTransaction<T>>[1]): Promise<T> {
    return withWorkerTransaction(
      this.pool,
      run,
      this.assumeRole === undefined ? {} : { assumeRole: this.assumeRole }
    );
  }

  public missingHandlerTypes(): readonly TypedJobType[] {
    return TYPED_JOB_TYPES.filter((jobType) => !this.handlers.has(jobType));
  }

  public assertCompleteRegistry(): void {
    const missing = this.missingHandlerTypes();
    if (missing.length > 0) {
      throw new Error(`worker handler registry is incomplete: ${missing.join(", ")}`);
    }
  }

  public async runOnce(): Promise<WorkerRunResult> {
    if (this.draining) return { status: "idle" };
    const pending = this.runtimeDatabaseLease
      ? withRuntimeDatabaseLease(this.runtimeDatabaseLease, () => this.runOnceWithLease())
      : this.runOnceWithLease();
    this.activeRuns.add(pending);
    try {
      return await pending;
    } finally {
      this.activeRuns.delete(pending);
    }
  }

  /** Stop new claims, preserving the runtime lease until existing work has settled. */
  public async drain(): Promise<void> {
    this.draining = true;
    await Promise.allSettled(this.activeRuns);
  }

  private async runOnceWithLease(): Promise<WorkerRunResult> {
    await this.beforeClaim?.();
    const claim = await this.transaction((client) =>
      claimTypedJobInTransaction(client, {
        leaseOwner: this.workerId,
        leaseSeconds: this.leaseSeconds
      })
    );
    this.onProgress?.();
    if (!claim.claimed) {
      return claim.rejectedJobId
        ? { status: "rejected_invalid_job", jobId: claim.rejectedJobId }
        : { status: "idle" };
    }

    const { job } = claim;
    const handler = this.handlers.get(job.envelope.jobType);
    const leaseAbort = new AbortController();
    let heartbeatInFlight: Promise<void> | null = null;
    let leaseLost = false;
    let heartbeatError = false;
    const heartbeat = setInterval(() => {
      if (heartbeatInFlight || leaseLost) return;
      const pending = this.transaction((client) =>
        heartbeatJobLeaseInTransaction(client, {
          jobId: job.jobId,
          leaseOwner: job.leaseOwner,
          attempt: job.attempt,
          leaseToken: job.leaseToken,
          leaseSeconds: this.leaseSeconds
        })
      )
        .then(({ extended }) => {
          if (!extended) {
            leaseLost = true;
            leaseAbort.abort("lease_lost");
          } else {
            this.onProgress?.();
          }
        })
        .catch(() => {
          heartbeatError = true;
          leaseAbort.abort("heartbeat_failed");
        })
        .finally(() => {
          if (heartbeatInFlight === pending) heartbeatInFlight = null;
        });
      heartbeatInFlight = pending;
    }, this.heartbeatMilliseconds);
    heartbeat.unref();

    let output: JsonValue | null = null;
    let executionResult: "succeeded" | "retryable_failure" | "permanent_failure" = "succeeded";
    let errorClass: string | null = null;
    try {
      if (!handler) {
        throw new TypedJobExecutionError("handler_unavailable", true);
      }
      output = await handler({ job, signal: leaseAbort.signal });
    } catch (error) {
      const failure = safeFailure(error);
      executionResult = failure.permanent ? "permanent_failure" : "retryable_failure";
      errorClass = failure.errorClass;
    } finally {
      clearInterval(heartbeat);
    }

    if (heartbeatInFlight) await heartbeatInFlight;

    if (leaseLost || heartbeatError) {
      return {
        status: "lease_lost",
        jobId: job.jobId,
        jobType: job.envelope.jobType,
        attempt: job.attempt,
        errorClass: heartbeatError ? "heartbeat_failed" : "lease_lost"
      };
    }

    const completion = await this.transaction((client) =>
      completeTypedJobInTransaction(client, {
        jobId: job.jobId,
        leaseOwner: job.leaseOwner,
        attempt: job.attempt,
        leaseToken: job.leaseToken,
        result: executionResult,
        resultSha256: completionDigest({ job, result: executionResult, errorClass, output }),
        ...(errorClass === null ? {} : { errorClass })
      })
    );
    if (!completion.completed) {
      return {
        status: "lease_lost",
        jobId: job.jobId,
        jobType: job.envelope.jobType,
        attempt: job.attempt,
        errorClass: "lease_lost"
      };
    }
    return {
      status:
        completion.state === "succeeded"
          ? "succeeded"
          : completion.state === "retry"
            ? "retry_scheduled"
            : "dead",
      jobId: job.jobId,
      jobType: job.envelope.jobType,
      attempt: job.attempt,
      ...(errorClass === null ? {} : { errorClass })
    };
  }

  public async run(signal: AbortSignal): Promise<void> {
    this.assertCompleteRegistry();
    while (!signal.aborted && !this.draining) {
      const result = await this.runOnce();
      if (result.status === "idle") await wait(this.pollMilliseconds, signal);
    }
  }
}
