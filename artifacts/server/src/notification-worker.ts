import { createHash, createHmac, randomBytes as nodeRandomBytes } from "node:crypto";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";

import {
  Rfc3339UtcSchema,
  canonicalSha256,
  safeHashEqual,
  sha256Hex,
  type JsonValue
} from "@boardagent/contracts";
import {
  claimNotificationDeliveryInTransaction,
  completeNotificationDeliveryInTransaction,
  createNotificationDeliveryInTransaction,
  enqueueNotificationDeadLetterAlertInTransaction,
  listNoticeWebhookTargetsInTransaction,
  readNotificationDeadLetterTargetInTransaction,
  readNotificationDeliveryStateInTransaction,
  reapExpiredNotificationLeasesInTransaction,
  withWorkerTransaction,
  type ClaimedNotificationDelivery,
  type NotificationDeliveryResultClass
} from "@boardagent/db";
import { uuidV7 } from "@boardagent/domain";
import type { Pool } from "pg";

import {
  TypedJobExecutionError,
  type TypedJobExecutionContext,
  type TypedJobHandler,
  type TypedJobType
} from "./worker.js";
import { WebhookResolutionTemporaryError, type WebhookSecurityPort } from "./webhook-security.js";
import {
  runWebhookAttempt,
  WebhookAttemptAbortedError,
  WebhookAttemptDeadlineError,
  WebhookPreconnectError
} from "./webhook-attempt.js";

const MAX_RESPONSE_BYTES = 65_536;
const DEFAULT_TIMEOUT_MILLISECONDS = 10_000;

export const NOTIFICATION_WORKER_JOB_TYPES = [
  "notice_fanout",
  "notification_dead_letter_alert",
  "notification_lease_reaper",
  "notification_retry",
  "webhook_delivery"
] as const satisfies readonly TypedJobType[];

export interface WebhookDeliveryTransportInput {
  readonly endpoint: string;
  readonly address: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Buffer;
  readonly signal: AbortSignal;
}

export interface WebhookDeliveryTransportResult {
  readonly statusCode: number;
  readonly responseSha256: string;
}

export interface WebhookDeliveryTransport {
  deliver(input: WebhookDeliveryTransportInput): Promise<WebhookDeliveryTransportResult>;
}

export class HttpsWebhookDeliveryTransport implements WebhookDeliveryTransport {
  public constructor(
    private readonly timeoutMilliseconds = DEFAULT_TIMEOUT_MILLISECONDS,
    private readonly maxResponseBytes = MAX_RESPONSE_BYTES
  ) {
    if (
      !Number.isInteger(timeoutMilliseconds) ||
      timeoutMilliseconds < 100 ||
      timeoutMilliseconds > 30_000
    ) {
      throw new RangeError(
        "webhook timeout must be an integer from 100 through 30000 milliseconds"
      );
    }
    if (
      !Number.isInteger(maxResponseBytes) ||
      maxResponseBytes < 0 ||
      maxResponseBytes > 1_048_576
    ) {
      throw new RangeError(
        "webhook response limit must be an integer from 0 through 1048576 bytes"
      );
    }
  }

  public deliver(input: WebhookDeliveryTransportInput): Promise<WebhookDeliveryTransportResult> {
    if (input.signal.aborted) {
      return Promise.reject(new Error("webhook delivery aborted"));
    }
    const family = isIP(input.address);
    if (family !== 4 && family !== 6) {
      return Promise.reject(new Error("validated webhook address has an invalid family"));
    }
    return new Promise((resolve, reject) => {
      let settled = false;
      let deadline: ReturnType<typeof setTimeout> | undefined;
      let request: ReturnType<typeof httpsRequest> | undefined;
      let socket: NonNullable<ReturnType<typeof httpsRequest>["socket"]> | undefined;
      let connectingSocketObserved = false;
      let connectionProgress = false;
      let detachResponse = (): void => {};
      const progress = (): void => {
        connectionProgress = true;
      };
      const observeSocket = (
        assigned: NonNullable<ReturnType<typeof httpsRequest>["socket"]>
      ): void => {
        socket = assigned;
        connectingSocketObserved = assigned.connecting === true && !assigned.destroyed;
        if (!connectingSocketObserved) progress();
        assigned.once("connect", progress);
        assigned.once("secureConnect", progress);
      };
      const finish = (run: () => void): void => {
        if (settled) return;
        settled = true;
        clearTimeout(deadline);
        input.signal.removeEventListener("abort", abort);
        request?.removeListener("socket", observeSocket);
        request?.removeListener("finish", progress);
        socket?.removeListener("connect", progress);
        socket?.removeListener("secureConnect", progress);
        detachResponse();
        run();
      };
      const fail = (error: unknown): void => {
        if (settled) return;
        // Settle before destroy: an already queued response end must not turn
        // cancellation, truncation or an oversized response into success.
        finish(() => reject(error));
        request?.destroy(error instanceof Error ? error : new Error("webhook delivery failed"));
      };
      const abort = (): void => fail(new Error("webhook delivery aborted"));
      try {
        const port = Number(new URL(input.endpoint).port || 443);
        request = httpsRequest(
          input.endpoint,
          {
            method: "POST",
            headers: input.headers,
            agent: false,
            family,
            lookup: (_hostname, options, callback) => {
              if (typeof options === "object" && options.all) {
                callback(null, [{ address: input.address, family }]);
              } else {
                callback(null, input.address, family);
              }
            }
          },
          (response) => {
            progress();
            if (settled) {
              response.on("error", () => {});
              response.destroy();
              return;
            }
            const hash = createHash("sha256");
            let length = 0;
            const data = (chunk: Buffer | string): void => {
              if (settled) return;
              const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
              length += bytes.length;
              if (length > this.maxResponseBytes) {
                fail(new Error("webhook response exceeds the bounded evidence limit"));
                return;
              }
              hash.update(bytes);
            };
            const end = (): void => {
              if (settled) return;
              const statusCode = response.statusCode;
              if (statusCode === undefined) {
                fail(new Error("webhook response omitted its status code"));
                return;
              }
              finish(() => resolve({ statusCode, responseSha256: hash.digest("hex") }));
            };
            const truncated = (): void =>
              fail(new Error("webhook response ended before completion"));
            response.on("data", data);
            response.on("end", end);
            response.on("aborted", truncated);
            response.on("close", truncated);
            // Retain this harmless error listener for errors emitted by destruction.
            response.on("error", fail);
            detachResponse = () => {
              response.removeListener("data", data);
              response.removeListener("end", end);
              response.removeListener("aborted", truncated);
              response.removeListener("close", truncated);
            };
          }
        );
        request.on("socket", observeSocket);
        request.on("finish", progress);
        // Keep this error listener after settlement to absorb destroy(error)'s event.
        request.on(
          "error",
          (error: NodeJS.ErrnoException & { address?: string; port?: number }) => {
            if (settled) return;
            const preconnect =
              connectingSocketObserved &&
              !connectionProgress &&
              !input.signal.aborted &&
              error.syscall === "connect" &&
              error.address === input.address &&
              error.port === port &&
              (error.code === "ECONNREFUSED" ||
                error.code === "ENETUNREACH" ||
                error.code === "EHOSTUNREACH");
            fail(preconnect ? new WebhookPreconnectError(input.address, { cause: error }) : error);
          }
        );
        input.signal.addEventListener("abort", abort, { once: true });
        // A socket idle timeout alone allows a slow response to hold the worker
        // indefinitely. This deadline covers the complete transport attempt.
        deadline = setTimeout(() => {
          fail(new Error("webhook delivery timed out"));
        }, this.timeoutMilliseconds);
        if (input.signal.aborted) {
          abort();
          return;
        }
        request.end(input.body);
      } catch (error) {
        fail(error);
      }
    });
  }
}

interface DeliveryAttemptOutcome {
  readonly resultClass: NotificationDeliveryResultClass;
  readonly httpStatus: number | null;
  readonly responseSha256: string | null;
  readonly errorClass: string | null;
}

function classifyStatus(result: WebhookDeliveryTransportResult): DeliveryAttemptOutcome {
  const status = result.statusCode;
  if (status >= 200 && status <= 299) {
    return {
      resultClass: "delivered",
      httpStatus: status,
      responseSha256: result.responseSha256,
      errorClass: null
    };
  }
  if (status >= 300 && status <= 399) {
    return {
      resultClass: "permanent_failure",
      httpStatus: status,
      responseSha256: result.responseSha256,
      errorClass: "webhook_redirect_refused"
    };
  }
  const retryable = status === 408 || status === 425 || status === 429 || status >= 500;
  return {
    resultClass: retryable ? "retryable_failure" : "permanent_failure",
    httpStatus: status,
    responseSha256: result.responseSha256,
    errorClass: retryable ? "webhook_retryable_status" : "webhook_permanent_status"
  };
}

function notificationSignatureInput(claim: ClaimedNotificationDelivery): Buffer {
  return Buffer.concat([
    Buffer.from(
      [
        "boardagent.webhook-signature.v1",
        claim.notificationJobId,
        claim.webhookId,
        claim.webhookGeneration.toString(10),
        claim.payloadSha256,
        ""
      ].join("\n"),
      "utf8"
    ),
    claim.canonicalPayload
  ]);
}

function deliveryRequestSha256(claim: ClaimedNotificationDelivery): string {
  return canonicalSha256({
    schemaVersion: "boardagent.webhook-attempt.v1",
    notificationJobId: claim.notificationJobId,
    webhookId: claim.webhookId,
    webhookGeneration: claim.webhookGeneration.toString(10),
    endpointSha256: claim.endpointSha256,
    payloadSha256: claim.payloadSha256,
    attempt: claim.attempt
  });
}

function operationalReference(kind: string, id: string): string {
  return canonicalSha256({
    schemaVersion: "boardagent.operational-reference.v1",
    kind,
    id
  });
}

export interface BoardAgentNotificationWorkerOptions {
  readonly webhookSecurity: WebhookSecurityPort;
  readonly transport?: WebhookDeliveryTransport;
  readonly workerId?: string;
  readonly leaseSeconds?: number;
  readonly newId?: () => string;
  readonly randomBytes?: (length: number) => Uint8Array;
  readonly now?: () => Date;
  readonly onOperationalAlert?: (alertClass: string, details: JsonValue) => void | Promise<void>;
  /** Test/local-owner seam only. Production connects as boardagent_worker directly. */
  readonly assumeRole?: "boardagent_worker";
}

export class BoardAgentNotificationWorker {
  private readonly transport: WebhookDeliveryTransport;
  private readonly workerId: string;
  private readonly leaseSeconds: number;
  private readonly newId: () => string;
  private readonly entropy: (length: number) => Buffer;
  private readonly now: () => Date;
  private readonly assumeRole: "boardagent_worker" | undefined;

  public constructor(
    private readonly pool: Pool,
    private readonly options: BoardAgentNotificationWorkerOptions
  ) {
    this.transport = options.transport ?? new HttpsWebhookDeliveryTransport();
    this.workerId = options.workerId ?? "notification-worker";
    if (!/^[A-Za-z0-9._:-]{1,128}$/u.test(this.workerId)) {
      throw new TypeError("notification worker ID is invalid");
    }
    this.leaseSeconds = options.leaseSeconds ?? 30;
    if (!Number.isInteger(this.leaseSeconds) || this.leaseSeconds < 15 || this.leaseSeconds > 300) {
      throw new RangeError("notification lease must be an integer from 15 through 300 seconds");
    }
    this.newId = options.newId ?? (() => uuidV7(Date.now(), nodeRandomBytes(10)));
    const source = options.randomBytes ?? nodeRandomBytes;
    this.entropy = (length) => {
      const bytes = Buffer.from(source(length));
      if (bytes.length !== length)
        throw new Error("notification entropy source returned wrong length");
      return bytes;
    };
    this.now = options.now ?? (() => new Date());
    this.assumeRole = options.assumeRole;
  }

  private transaction<T>(run: Parameters<typeof withWorkerTransaction<T>>[1]): Promise<T> {
    return withWorkerTransaction(
      this.pool,
      run,
      this.assumeRole === undefined ? {} : { assumeRole: this.assumeRole }
    );
  }

  public readonly noticeFanoutHandler: TypedJobHandler = async ({ job }) => {
    const envelope = job.envelope;
    if (envelope.jobType !== "notice_fanout") {
      throw new TypedJobExecutionError("notification_job_type_mismatch", true);
    }
    const targets = await this.transaction((client) =>
      listNoticeWebhookTargetsInTransaction(client, envelope.parameters.noticeId)
    );
    let created = 0;
    let replayed = 0;
    for (const target of targets) {
      if (
        target.organizationId !== envelope.organizationId ||
        target.boardId !== envelope.boardId
      ) {
        throw new TypedJobExecutionError("notification_target_binding_mismatch", true);
      }
      const result = await this.transaction((client) =>
        createNotificationDeliveryInTransaction(client, {
          notificationJobId: this.newId(),
          noticeId: envelope.parameters.noticeId,
          webhookId: target.webhookId,
          wakeClass: target.wakeClass,
          randomWakeId: this.entropy(32),
          occurredAt: Rfc3339UtcSchema.parse(this.now().toISOString())
        })
      );
      if (result.replayed) replayed += 1;
      else created += 1;
    }
    return { targets: targets.length, created, replayed };
  };

  private async claim(
    notificationJobId: string | null
  ): Promise<ClaimedNotificationDelivery | null> {
    return this.transaction((client) =>
      claimNotificationDeliveryInTransaction(client, {
        notificationJobId,
        leaseOwner: this.workerId,
        leaseSeconds: this.leaseSeconds
      })
    );
  }

  private async complete(
    claim: ClaimedNotificationDelivery,
    requestSha256: string,
    outcome: DeliveryAttemptOutcome
  ): Promise<"delivered" | "retry" | "dead" | "cancelled"> {
    const result = await this.transaction(async (client) => {
      const completed = await completeNotificationDeliveryInTransaction(client, {
        attemptId: this.newId(),
        auditEventId: this.newId(),
        notificationJobId: claim.notificationJobId,
        leaseOwner: this.workerId,
        attempt: claim.attempt,
        requestSha256,
        resultClass: outcome.resultClass,
        errorClass: outcome.errorClass,
        httpStatus: outcome.httpStatus,
        responseSha256: outcome.responseSha256
      });
      if (completed.completed && completed.state === "dead" && claim.sourceKind === "notice") {
        const alert = await enqueueNotificationDeadLetterAlertInTransaction(client, {
          jobId: this.newId(),
          notificationJobId: claim.notificationJobId
        });
        if (!alert) {
          throw new Error("dead notice delivery did not produce its durable alert job");
        }
      }
      return completed;
    });
    if (!result.completed || !result.state) {
      throw new TypedJobExecutionError("notification_lease_lost", false);
    }
    return result.state;
  }

  private async executeClaim(
    claim: ClaimedNotificationDelivery,
    signal: AbortSignal
  ): Promise<JsonValue> {
    const requestSha256 = deliveryRequestSha256(claim);
    let deliveryStarted = false;
    let outcome: DeliveryAttemptOutcome;
    let prepared: Omit<WebhookDeliveryTransportInput, "address" | "signal"> | undefined;
    try {
      const transportResult = await runWebhookAttempt({
        signal,
        validate: async () => {
          const endpoint = this.options.webhookSecurity.openEndpoint({
            organizationId: claim.organizationId,
            memberId: claim.memberId,
            webhookId: claim.webhookId,
            keyId: claim.keyId,
            endpointCiphertext: claim.endpointCiphertext
          });
          const secret = this.options.webhookSecurity.openSecret({
            organizationId: claim.organizationId,
            memberId: claim.memberId,
            webhookId: claim.webhookId,
            keyId: claim.keyId,
            secretCiphertext: claim.secretCiphertext
          });
          if (
            !safeHashEqual(sha256Hex(endpoint), claim.endpointSha256) ||
            !safeHashEqual(sha256Hex(Buffer.from(secret, "base64url")), claim.secretSha256)
          ) {
            throw new Error("webhook protected material hash mismatch");
          }
          const validated = await this.options.webhookSecurity.validateEndpoint(endpoint);
          if (
            validated.endpoint !== endpoint ||
            !safeHashEqual(validated.endpointSha256, claim.endpointSha256)
          ) {
            throw new Error("webhook endpoint changed during fresh validation");
          }
          const signature = createHmac("sha256", Buffer.from(secret, "base64url"))
            .update(notificationSignatureInput(claim))
            .digest("hex");
          prepared = {
            endpoint,
            headers: {
              "content-type": "application/json",
              "content-length": String(claim.canonicalPayload.length),
              "user-agent": "BoardAgent-Webhook/1",
              "x-boardagent-delivery": claim.notificationJobId,
              "x-boardagent-event": claim.wakeClass,
              "x-boardagent-generation": claim.webhookGeneration.toString(10),
              "x-boardagent-signature": `v1=${signature}`,
              "x-boardagent-wake-id": claim.randomWakeId.toString("base64url")
            },
            body: claim.canonicalPayload
          };
          return validated.resolvedAddresses;
        },
        deliver: (address, attemptSignal) => {
          if (!prepared) throw new Error("webhook validated request is unavailable");
          deliveryStarted = true;
          return this.transport.deliver({ ...prepared, address, signal: attemptSignal });
        }
      });
      outcome = classifyStatus(transportResult);
    } catch (error) {
      const validationFailure =
        !deliveryStarted &&
        !(error instanceof WebhookAttemptDeadlineError) &&
        !(error instanceof WebhookAttemptAbortedError) &&
        !(error instanceof WebhookResolutionTemporaryError);
      outcome = {
        resultClass: validationFailure ? "permanent_failure" : "retryable_failure",
        httpStatus: null,
        responseSha256: null,
        errorClass: validationFailure
          ? "webhook_security_validation_failed"
          : "webhook_transport_failure"
      };
    }
    const state = await this.complete(claim, requestSha256, outcome);
    if (state === "retry") {
      throw new TypedJobExecutionError(outcome.errorClass ?? "webhook_retryable_failure", false);
    }
    if (state === "dead") {
      throw new TypedJobExecutionError(outcome.errorClass ?? "webhook_permanent_failure", true);
    }
    return {
      notificationJobId: claim.notificationJobId,
      state,
      statusCode: outcome.httpStatus,
      responseSha256: outcome.responseSha256
    };
  }

  public readonly deliveryHandler: TypedJobHandler = async (context: TypedJobExecutionContext) => {
    if (
      context.job.envelope.jobType !== "webhook_delivery" &&
      context.job.envelope.jobType !== "notification_retry"
    ) {
      throw new TypedJobExecutionError("notification_job_type_mismatch", true);
    }
    const notificationJobId = context.job.envelope.parameters.notificationJobId;
    const claim = await this.claim(notificationJobId);
    if (!claim) {
      const state = await this.transaction((client) =>
        readNotificationDeliveryStateInTransaction(client, notificationJobId)
      );
      if (state === "delivered" || state === "cancelled") {
        return { notificationJobId, state, replayed: true };
      }
      throw new TypedJobExecutionError(
        state === "dead" || state === null
          ? "notification_delivery_unavailable"
          : "notification_delivery_not_ready",
        state === "dead" || state === null
      );
    }
    if (
      claim.organizationId !== context.job.envelope.organizationId ||
      claim.boardId !== context.job.envelope.boardId ||
      (claim.sourceKind !== "notice" &&
        !(
          claim.sourceKind === "test" &&
          claim.boardId === null &&
          claim.wakeClass === "security" &&
          context.job.envelope.jobType === "webhook_delivery"
        ))
    ) {
      throw new TypedJobExecutionError("notification_delivery_binding_mismatch", true);
    }
    return this.executeClaim(claim, context.signal);
  };

  public readonly notificationLeaseReaperHandler: TypedJobHandler = async ({ job }) => {
    const envelope = job.envelope;
    if (envelope.jobType !== "notification_lease_reaper") {
      throw new TypedJobExecutionError("notification_reaper_type_mismatch", true);
    }
    const attemptIds = Array.from({ length: 100 }, () => this.newId());
    return this.transaction(async (client) => {
      const result = await reapExpiredNotificationLeasesInTransaction(client, {
        organizationId: envelope.organizationId,
        attemptIds
      });
      let alertsEnqueued = 0;
      let alertsReplayed = 0;
      for (const notificationJobId of result.deadNotificationIds) {
        const target = await readNotificationDeadLetterTargetInTransaction(
          client,
          notificationJobId
        );
        if (!target) continue;
        if (target.organizationId !== envelope.organizationId) {
          throw new TypedJobExecutionError("notification_reaper_binding_mismatch", true);
        }
        const alert = await enqueueNotificationDeadLetterAlertInTransaction(client, {
          jobId: this.newId(),
          notificationJobId
        });
        if (!alert) {
          throw new Error("dead notice delivery did not produce its durable alert job");
        }
        if (alert.replayed) alertsReplayed += 1;
        else alertsEnqueued += 1;
      }
      return {
        reaped: result.reaped,
        retried: result.retried,
        dead: result.dead,
        alertsEnqueued,
        alertsReplayed
      };
    });
  };

  public readonly notificationDeadLetterAlertHandler: TypedJobHandler = async ({ job, signal }) => {
    const envelope = job.envelope;
    if (envelope.jobType !== "notification_dead_letter_alert") {
      throw new TypedJobExecutionError("notification_alert_type_mismatch", true);
    }
    const target = await this.transaction((client) =>
      readNotificationDeadLetterTargetInTransaction(client, envelope.parameters.notificationJobId)
    );
    if (
      !target ||
      target.organizationId !== envelope.organizationId ||
      target.boardId !== envelope.boardId ||
      target.notificationJobId !== envelope.subjectId
    ) {
      throw new TypedJobExecutionError("notification_alert_binding_mismatch", true);
    }
    if (signal.aborted) {
      throw new TypedJobExecutionError("notification_alert_aborted", false);
    }
    if (!this.options.onOperationalAlert) {
      throw new TypedJobExecutionError("operational_alert_unavailable", false);
    }
    const details = {
      schemaVersion: "boardagent.operational-alert.notification-dead-letter.v1",
      alertJobRef: operationalReference("job", job.jobId),
      organizationRef: operationalReference("organization", target.organizationId),
      boardRef: operationalReference("board", target.boardId),
      notificationJobRef: operationalReference("notification_job", target.notificationJobId)
    } as const satisfies JsonValue;
    try {
      await this.options.onOperationalAlert("notification_dead_letter", details);
    } catch {
      throw new TypedJobExecutionError("operational_alert_delivery_failed", false);
    }
    return { alertClass: "notification_dead_letter", ...details };
  };

  public handlers(): ReadonlyMap<TypedJobType, TypedJobHandler> {
    return new Map<TypedJobType, TypedJobHandler>([
      ["notice_fanout", this.noticeFanoutHandler],
      ["notification_dead_letter_alert", this.notificationDeadLetterAlertHandler],
      ["notification_lease_reaper", this.notificationLeaseReaperHandler],
      ["notification_retry", this.deliveryHandler],
      ["webhook_delivery", this.deliveryHandler]
    ]);
  }

  public async runOneTestWake(): Promise<JsonValue | null> {
    const claim = await this.claim(null);
    return claim ? this.executeClaim(claim, new AbortController().signal) : null;
  }
}
