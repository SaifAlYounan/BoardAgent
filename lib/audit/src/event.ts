import { z } from "zod";
import { KeyLifecycleChangedSchema } from "./key-lifecycle-event.js";

import {
  canonicalJson,
  EVENT_IDS,
  Rfc3339UtcSchema,
  safeHashEqual,
  Sha256HexSchema,
  sha256Hex,
  UuidV7Schema,
  type JsonValue
} from "@boardagent/contracts";

export const AUDIT_DOMAIN = "boardagent.audit.event.v1";
export const GENESIS_HASH = "0".repeat(64);

export type AuditEventType = (typeof EVENT_IDS)[number];

function createJsonValueSchema(): z.ZodType<JsonValue> {
  return z.union([
    z.boolean(),
    z.null(),
    z.number().finite(),
    z.string(),
    z.array(JsonValueSchema),
    z.record(z.string(), JsonValueSchema)
  ]);
}

const JsonValueSchema: z.ZodType<JsonValue> = z.lazy(createJsonValueSchema);

function createAuditEventBodySchema(): z.ZodType<AuditEventBody> {
  return z
    .object({
      eventId: UuidV7Schema,
      eventType: z.enum(EVENT_IDS),
      actorMemberId: UuidV7Schema.nullable(),
      actorClientId: UuidV7Schema.nullable(),
      tokenJti: UuidV7Schema.nullable(),
      entityType: z.string().regex(/^[a-z][a-z0-9_]{1,63}$/u),
      entityId: z.string().min(1).max(2048),
      boardId: UuidV7Schema.nullable(),
      occurredAt: Rfc3339UtcSchema,
      origin: z.enum([
        "mcp",
        "oauth",
        "browser",
        "worker",
        "scheduler",
        "migration",
        "restore",
        "cli"
      ]),
      details: z.record(z.string().regex(/^[a-z][A-Za-z0-9_]{0,127}$/u), JsonValueSchema),
      schemaVersion: z.literal(1)
    })
    .strict()
    .superRefine((body, context) => {
      if (body.eventType !== "key_lifecycle_changed") return;
      const evidence = KeyLifecycleChangedSchema.safeParse(body.details);
      if (
        !evidence.success ||
        body.origin !== "cli" ||
        body.actorMemberId !== null ||
        body.actorClientId !== null ||
        body.tokenJti !== null ||
        body.boardId !== null ||
        body.entityType !== "key_lifecycle_operation" ||
        body.entityId !== evidence.data.operationId ||
        body.occurredAt !== evidence.data.recordedAt
      )
        context.addIssue({ code: "custom", message: "invalid operator key lifecycle event" });
    });
}

export const AuditEventBodySchema: z.ZodType<AuditEventBody> = z.lazy(createAuditEventBodySchema);

export interface AuditEventBody {
  readonly eventId: string;
  readonly eventType: AuditEventType;
  readonly actorMemberId: string | null;
  readonly actorClientId: string | null;
  readonly tokenJti: string | null;
  readonly entityType: string;
  readonly entityId: string;
  readonly boardId: string | null;
  readonly occurredAt: string;
  readonly origin: string;
  readonly details: Readonly<Record<string, JsonValue>>;
  readonly schemaVersion: 1;
}

export interface AuditEvent extends AuditEventBody {
  readonly sequence: bigint;
  readonly previousHash: string;
  readonly eventHash: string;
}

interface HashMaterial extends AuditEventBody {
  readonly domain: typeof AUDIT_DOMAIN;
  readonly sequence: string;
  readonly previousHash: string;
}

export function eventHash(sequence: bigint, previousHash: string, body: AuditEventBody): string {
  if (sequence < 1n) throw new RangeError("audit sequence must be positive");
  Sha256HexSchema.parse(previousHash);
  const validated = AuditEventBodySchema.parse(body) as AuditEventBody;
  return hashValidatedEvent(sequence, previousHash, validated);
}

// Private to this module: both entry points validate the body before reaching it.
function hashValidatedEvent(
  sequence: bigint,
  previousHash: string,
  validated: AuditEventBody
): string {
  const material: HashMaterial = {
    domain: AUDIT_DOMAIN,
    sequence: sequence.toString(10),
    previousHash,
    ...validated
  };
  return sha256Hex(canonicalJson(material));
}

export function appendEvent(previous: AuditEvent | undefined, body: AuditEventBody): AuditEvent {
  const validated = AuditEventBodySchema.parse(body) as AuditEventBody;
  const sequence = previous ? previous.sequence + 1n : 1n;
  const previousHash = previous?.eventHash ?? GENESIS_HASH;
  return {
    ...validated,
    sequence,
    previousHash,
    eventHash: eventHash(sequence, previousHash, validated)
  };
}

export type ChainVerification =
  | { readonly valid: true; readonly count: bigint; readonly headHash: string }
  | { readonly valid: false; readonly firstBreakSequence: bigint; readonly reason: string };

/** Incremental form of the same chain oracle; keeps no event bodies in memory. */
export class AuditChainVerifier {
  private previousHash = GENESIS_HASH;
  private expectedSequence = 1n;
  private failure: Extract<ChainVerification, { valid: false }> | undefined;

  public add(event: AuditEvent): Extract<ChainVerification, { valid: false }> | undefined {
    return this.addWithHash(event, () => {
      const {
        sequence: _sequence,
        previousHash: _previousHash,
        eventHash: _eventHash,
        ...body
      } = event;
      return eventHash(event.sequence, event.previousHash, body);
    });
  }

  /** Decode and validate persisted bytes once, then apply the same chain oracle.
   * Returning an event only establishes its schema and canonical representation;
   * finish() still determines chain validity. The caller must also check its stored
   * columns. Returning later decoded events preserves that caller's error precedence
   * even after the chain has recorded its first failure.
   */
  public addCanonicalEvent(input: {
    readonly canonicalPayload: Buffer;
    readonly sequence: bigint;
    readonly previousHash: string;
    readonly eventHash: string;
  }):
    | { readonly event: AuditEvent }
    | { readonly reason: "event_schema_invalid" | "event_manifest_not_canonical" } {
    const reject = (reason: "event_schema_invalid" | "event_manifest_not_canonical") => {
      this.failure ??= { valid: false, firstBreakSequence: input.sequence, reason };
      return { reason };
    };
    let body: AuditEventBody;
    try {
      body = AuditEventBodySchema.parse(JSON.parse(input.canonicalPayload.toString("utf8")));
    } catch {
      return reject("event_schema_invalid");
    }
    try {
      if (!input.canonicalPayload.equals(Buffer.from(canonicalJson(body))))
        return reject("event_manifest_not_canonical");
    } catch (error) {
      reject("event_manifest_not_canonical");
      throw error;
    }
    const event: AuditEvent = {
      ...body,
      sequence: input.sequence,
      previousHash: input.previousHash,
      eventHash: input.eventHash
    };
    this.addWithHash(event, () => hashValidatedEvent(event.sequence, event.previousHash, body));
    return { event };
  }

  private addWithHash(
    event: AuditEvent,
    recompute: () => string
  ): Extract<ChainVerification, { valid: false }> | undefined {
    if (this.failure) return this.failure;
    if (event.sequence !== this.expectedSequence) {
      return (this.failure = {
        valid: false,
        firstBreakSequence: this.expectedSequence,
        reason: "sequence_gap_or_reorder"
      });
    }
    if (!safeHashEqual(event.previousHash, this.previousHash)) {
      return (this.failure = {
        valid: false,
        firstBreakSequence: event.sequence,
        reason: "previous_hash_mismatch"
      });
    }
    let recomputed: string;
    try {
      recomputed = recompute();
    } catch {
      return (this.failure = {
        valid: false,
        firstBreakSequence: event.sequence,
        reason: "event_schema_invalid"
      });
    }
    if (!safeHashEqual(event.eventHash, recomputed)) {
      return (this.failure = {
        valid: false,
        firstBreakSequence: event.sequence,
        reason: "event_hash_mismatch"
      });
    }
    this.previousHash = event.eventHash;
    this.expectedSequence += 1n;
    return undefined;
  }

  public finish(expected?: {
    readonly count: bigint;
    readonly headHash: string;
  }): ChainVerification {
    if (this.failure) return this.failure;
    const count = this.expectedSequence - 1n;
    if (expected && expected.count !== count) {
      return { valid: false, firstBreakSequence: count + 1n, reason: "truncation_or_extension" };
    }
    if (expected && !safeHashEqual(expected.headHash, this.previousHash)) {
      return { valid: false, firstBreakSequence: count, reason: "head_hash_mismatch" };
    }
    return { valid: true, count, headHash: this.previousHash };
  }
}

export function verifyChain(
  events: readonly AuditEvent[],
  expected?: { readonly count: bigint; readonly headHash: string }
): ChainVerification {
  const verifier = new AuditChainVerifier();
  for (const event of events) {
    const failure = verifier.add(event);
    if (failure) return failure;
  }
  return verifier.finish(expected);
}
