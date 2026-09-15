import { generateKeyPairSync, type KeyObject } from "node:crypto";

import { describe, expect, it } from "vitest";
import type { z } from "zod";

import {
  appendEvent,
  signCheckpoint,
  signRecoveryCheckpoint,
  AuditRecoveryRequestSchema,
  type SignedAuditRecoveryCheckpoint,
  signAuditExportAttestation,
  verifyOfflineAuditExport,
  type AuditCheckpointPayload,
  type AuditEvent,
  type AuditEventBody,
  type OfflineAuditExportExpectation,
  type OfflineAuditExportVerification
} from "../../lib/audit/src/index.js";
import {
  UuidV7Schema,
  canonicalJson,
  canonicalSha256,
  sha256Hex,
  type JsonValue
} from "../../lib/contracts/src/index.js";

type Row = Readonly<Record<string, JsonValue>>;

const id = (suffix: number): string =>
  `018f0000-0000-7000-8000-${suffix.toString(16).padStart(12, "0")}`;
const organizationId = id(1);
const signingKeyId = id(2);

function body(suffix: number, boardId: string | null, entityId = id(200 + suffix)): AuditEventBody {
  return {
    eventId: id(100 + suffix),
    eventType: "context_read",
    actorMemberId: id(300 + suffix),
    actorClientId: id(400 + suffix),
    tokenJti: id(500 + suffix),
    entityType: "test_record",
    entityId,
    boardId,
    occurredAt: `2026-09-01T12:00:0${String(suffix)}Z`,
    origin: "mcp",
    details: { suffix },
    schemaVersion: 1
  };
}

function exportedEventRow(event: AuditEvent): Row {
  const { sequence, previousHash, eventHash, ...eventBody } = event;
  const entityUuid = UuidV7Schema.safeParse(event.entityId);
  return {
    id: event.eventId,
    sequence: sequence.toString(10),
    organization_id: organizationId,
    board_id: event.boardId,
    event_type: event.eventType,
    schema_version: "boardagent.audit-event.v1",
    actor_member_id: event.actorMemberId,
    acting_for_member_id: null,
    client_id: event.actorClientId,
    token_jti: event.tokenJti,
    consent_record_id: null,
    object_type: event.entityType,
    object_id: entityUuid.success ? entityUuid.data : null,
    object_version: null,
    canonical_payload: `\\x${Buffer.from(canonicalJson(eventBody), "utf8").toString("hex")}`,
    previous_event_sha256: `\\x${previousHash}`,
    event_sha256: `\\x${eventHash}`,
    occurred_at: event.occurredAt
  };
}

function component(name: string, rows: readonly JsonValue[]): Buffer {
  return Buffer.from(
    canonicalJson({
      schemaVersion: "boardagent.export-component.v1",
      name,
      rowEncoding: "postgres-text-v1",
      rows
    }),
    "utf8"
  );
}

function signedCheckpointRow(
  privateKey: KeyObject,
  payload: AuditCheckpointPayload,
  changes: Row = {}
): { readonly row: Row; readonly manifestSha256: string } {
  const checkpoint = signCheckpoint(payload, privateKey);
  const manifestBytes = Buffer.from(canonicalJson(checkpoint.payload), "utf8");
  const manifestSha256 = sha256Hex(manifestBytes);
  return {
    row: {
      id: checkpoint.payload.checkpointId,
      organization_id: organizationId,
      first_sequence: checkpoint.payload.firstSequence,
      last_sequence: checkpoint.payload.lastSequence,
      first_event_sha256: `\\x${checkpoint.payload.firstEventSha256}`,
      last_event_sha256: `\\x${checkpoint.payload.lastEventSha256}`,
      canonical_manifest: `\\x${manifestBytes.toString("hex")}`,
      manifest_sha256: `\\x${manifestSha256}`,
      signature: `\\x${Buffer.from(checkpoint.signatureBase64Url, "base64url").toString("hex")}`,
      signing_key_id: checkpoint.payload.signingKeyId,
      created_at: checkpoint.payload.issuedAt.replace("T", " ").replace("Z", "+00"),
      ...changes
    },
    manifestSha256
  };
}

function fixture(
  boardId: string | null = null,
  secondEntityId = id(202),
  fractional: boolean | string = false,
  eventDay = "2026-09-01"
) {
  const evidence = generateKeyPairSync("ed25519");
  const bodies = [body(1, boardId), body(2, boardId, secondEntityId)] as const;
  // `fractional` selects the signed fraction: none, the six-digit default, or exact digits.
  const fraction = fractional === true ? ".123456" : fractional === false ? "" : fractional;
  for (const event of bodies) {
    Object.assign(event, {
      occurredAt: event.occurredAt.replace("2026-09-01", eventDay).replace("Z", `${fraction}Z`)
    });
  }
  const events = [appendEvent(undefined, bodies[0])] as AuditEvent[];
  events.push(appendEvent(events[0], bodies[1]));
  const checkpointPayload: AuditCheckpointPayload = {
    schema: "boardagent.audit.checkpoint.v1",
    checkpointId: id(3),
    instanceId: id(4),
    organizationId,
    auditSchema: "boardagent.audit-event.v1",
    firstSequence: "1",
    lastSequence: "2",
    firstEventSha256: events[0]!.eventHash,
    lastEventSha256: events[1]!.eventHash,
    issuedAt: `2026-09-01T12:01:00${fraction}Z`,
    signingKeyId,
    keyId: "evidence-key-1"
  };
  const checkpoint = signedCheckpointRow(evidence.privateKey, checkpointPayload);
  const expectation: OfflineAuditExportExpectation = {
    organizationId,
    boardId,
    rangeFirstSequence: "1",
    rangeLastSequence: "2",
    auditHeadSequence: "2",
    auditHeadSha256: events[1]!.eventHash,
    latestCheckpointSha256: checkpoint.manifestSha256
  };
  const signingKey = {
    id: signingKeyId,
    kid: "evidence-key-1",
    algorithm: "EdDSA" as const,
    public_jwk: evidence.publicKey.export({ format: "jwk" }) as JsonValue
  };
  return {
    bodies,
    checkpointPayload,
    checkpointRow: checkpoint.row,
    eventRows: events.map(exportedEventRow),
    events,
    expectation,
    privateKey: evidence.privateKey,
    signingKey,
    trust: {
      schema_version: "boardagent.trusted-evidence-keys.v1" as const,
      keys: [signingKey]
    }
  };
}

function verify(
  value: ReturnType<typeof fixture>,
  changes: {
    readonly eventRows?: readonly Row[];
    readonly checkpointRows?: readonly Row[];
    readonly expectation?: OfflineAuditExportExpectation;
    readonly trust?: unknown;
    readonly eventBytes?: Uint8Array;
    readonly checkpointBytes?: Uint8Array;
  } = {}
): OfflineAuditExportVerification {
  return verifyOfflineAuditExport(
    changes.eventBytes ?? component("audit:events", changes.eventRows ?? value.eventRows),
    changes.checkpointBytes ??
      component("audit:checkpoints", changes.checkpointRows ?? [value.checkpointRow]),
    changes.expectation ?? value.expectation,
    changes.trust ?? value.trust
  );
}

function expectInvalid(
  actual: OfflineAuditExportVerification,
  reason: string,
  firstBreakSequence: string | null = null
): void {
  expect(actual).toEqual({ valid: false, firstBreakSequence, reason });
}

function redacted(row: Row): Row {
  return {
    sequence: row["sequence"]!,
    previous_event_sha256: row["previous_event_sha256"]!,
    event_sha256: row["event_sha256"]!,
    redacted: "true"
  };
}

describe("offline audit-export chain boundaries", () => {
  it.each([
    ["2026-09-01 16:00:01.123456+04", "2026-09-01T16:01:00.123456+04:00"],
    ["2026-09-01T06:30:01.123456-05:30", "2026-09-01 06:31:00.123456-05:30"],
    ["2026-09-01 12:00:31.123456+00:00:30", "2026-09-01 12:01:30.123456+00:00:30"],
    ["2026-09-01T12:00:01.123456+00:00", "2026-09-01 12:01:00.123456-00:00"],
    ["2026-09-02T12:00:00.123456+23:59:59", "2026-09-02 12:00:59.123456+23:59:59"],
    ["2026-08-31T12:00:02.123456-23:59:59", "2026-08-31 12:01:01.123456-23:59:59"]
  ])("accepts equivalent PostgreSQL offset instants %s", (eventTime, checkpointTime) => {
    const value = fixture(null, id(202), true);
    expect(
      verify(value, {
        eventRows: [{ ...value.eventRows[0]!, occurred_at: eventTime }, value.eventRows[1]!],
        checkpointRows: [{ ...value.checkpointRow, created_at: checkpointTime }]
      }).valid
    ).toBe(true);
  });

  it.each([
    [".5", "2026-09-01T12:00:01.500000+00:00", "2026-09-01 12:01:00.5+00"],
    [".5", "2026-09-01 16:00:01.5+04", "2026-09-01T16:01:00.500+04:00"],
    [".000001", "2026-09-01T12:00:01.000001Z", "2026-09-01 12:01:00.000001+00:00"],
    ["", "2026-09-01T12:00:01.0Z", "2026-09-01 12:01:00.000000+00"]
  ])(
    "accepts equal instants whose signed fraction %s is written with other digit counts",
    (signedFraction, eventTime, checkpointTime) => {
      const value = fixture(null, id(202), signedFraction);
      expect(
        verify(value, {
          eventRows: [{ ...value.eventRows[0]!, occurred_at: eventTime }, value.eventRows[1]!],
          checkpointRows: [{ ...value.checkpointRow, created_at: checkpointTime }]
        }).valid
      ).toBe(true);
    }
  );

  // Every exported form below would equal the signed instant 12:00:01.123456Z only if a
  // guard were missing: anchors, the calendar check, or the 23/59/59 offset bounds.
  it.each([
    ["x2026-09-01T12:00:01.123456Z", "leading text before an otherwise exact instant"],
    ["2026-09-01T12:00:01.123456Zx", "trailing text after an otherwise exact instant"],
    ["2026-09-01T12:00:01.123456+00:00 ", "trailing whitespace"],
    ["2026-09-02T12:00:01.123456+24:00", "an offset of 24 hours"],
    ["2026-09-01T13:00:01.123456+00:60", "an offset of 60 minutes"],
    ["2026-09-01T12:01:01.123456+00:00:60", "an offset of 60 seconds"],
    ["2026-09-01T16:00:01.123456+4", "a one-digit offset hour"],
    ["2026-09-01T16:30:01.123456+04:3", "a one-digit offset minute"],
    ["2026-09-01T12:00:01.123456+00:00:00:00", "a fourth offset field"],
    ["2026-09-01T12:00:01.1234567Z", "seven fraction digits"]
  ])("rejects the exported event instant %s (%s)", (occurredAt) => {
    const value = fixture(null, id(202), true);
    expectInvalid(
      verify(value, {
        eventRows: [{ ...value.eventRows[0]!, occurred_at: occurredAt }, value.eventRows[1]!]
      }),
      "event_hash_or_projection_mismatch",
      "1"
    );
  });

  it.each(["2026-02-30T12:00:01Z", "2026-02-30 12:00:01+00", "2026-02-30T16:00:01+04"])(
    "rejects an impossible exported calendar date %s even though Date would normalize it",
    (occurredAt) => {
      // The signed instant is 2 March; Date.parse turns 30 February into exactly that.
      const value = fixture(null, id(202), false, "2026-03-02");
      expect(verify(value).valid).toBe(true);
      expectInvalid(
        verify(value, {
          eventRows: [{ ...value.eventRows[0]!, occurred_at: occurredAt }, value.eventRows[1]!]
        }),
        "event_hash_or_projection_mismatch",
        "1"
      );
    }
  );

  it.each([
    ["2026-09-02 12:01:00.123456+24:00", "an offset of 24 hours"],
    ["2026-09-01 12:01:00.123456+00:00:60", "an offset of 60 seconds"],
    ["2026-09-01T12:01:00.123456Z\n", "a trailing newline"]
  ])("rejects the exported checkpoint instant %s (%s)", (createdAt) => {
    const value = fixture(null, id(202), true);
    expectInvalid(
      verify(value, { checkpointRows: [{ ...value.checkpointRow, created_at: createdAt }] }),
      "checkpoint_signature_or_projection_mismatch",
      "2"
    );
  });

  it.each(["2026-09-01T12:00:01.123457Z", "2026-02-30T12:00:01.123456Z", "not-a-timestamp"])(
    "rejects a changed or invalid exact event instant %s",
    (occurredAt) => {
      const value = fixture(null, id(202), true);
      expectInvalid(
        verify(value, {
          eventRows: [{ ...value.eventRows[0]!, occurred_at: occurredAt }, value.eventRows[1]!]
        }),
        "event_hash_or_projection_mismatch",
        "1"
      );
    }
  );

  it("rejects a changed exported event timestamp even when its signed body is untouched", () => {
    const value = fixture();
    expect(verify(value).valid).toBe(true);
    expectInvalid(
      verify(value, {
        eventRows: [
          { ...value.eventRows[0]!, occurred_at: "2026-09-02T12:00:01Z" },
          value.eventRows[1]!
        ]
      }),
      "event_hash_or_projection_mismatch",
      "1"
    );
  });

  it("rejects a changed exported checkpoint timestamp even when its signed manifest is untouched", () => {
    const value = fixture();
    expect(verify(value).valid).toBe(true);
    expectInvalid(
      verify(value, {
        checkpointRows: [{ ...value.checkpointRow, created_at: "2026-09-02 12:01:00+00" }]
      }),
      "checkpoint_signature_or_projection_mismatch",
      "2"
    );
  });

  it("accepts complete legacy proofs and refuses unprovable legacy redactions", () => {
    const full = fixture();
    expect(verify(full)).toEqual({
      valid: true,
      eventCount: "2",
      firstSequence: "1",
      lastSequence: "2",
      headHash: full.events[1]!.eventHash,
      checkpointCount: 1,
      anchorSequence: "2",
      latestCheckpointLastSequence: "2"
    });

    const board = fixture(id(50));
    expectInvalid(
      verify(board, { eventRows: [redacted(board.eventRows[0]!), board.eventRows[1]!] }),
      "legacy_redacted_proof_unavailable"
    );

    const suffix = fixture();
    expect(
      verify(suffix, {
        eventRows: [suffix.eventRows[1]!],
        expectation: {
          ...suffix.expectation,
          rangeFirstSequence: "2",
          rangeLastSequence: "2"
        }
      })
    ).toMatchObject({ valid: true, eventCount: "1", firstSequence: "2", anchorSequence: "2" });

    const externalEntity = fixture(null, "external-record-2");
    expect(verify(externalEntity)).toMatchObject({ valid: true, lastSequence: "2" });
  });

  it("reports each empty, redaction, genesis, sequence, and previous-link break exactly", () => {
    const value = fixture();
    expectInvalid(verify(value, { eventRows: [] }), "audit_export_empty");
    expectInvalid(
      verify(value, { eventRows: [redacted(value.eventRows[0]!)] }),
      "unexpected_redaction",
      "1"
    );
    expectInvalid(
      verify(value, {
        eventRows: [
          { ...value.eventRows[0]!, previous_event_sha256: `\\x${"f".repeat(64)}` },
          value.eventRows[1]!
        ]
      }),
      "genesis_hash_mismatch",
      "1"
    );
    expectInvalid(
      verify(value, {
        eventRows: [value.eventRows[0]!, { ...value.eventRows[1]!, sequence: "3" }]
      }),
      "sequence_gap_or_reorder",
      "2"
    );
    expectInvalid(
      verify(value, {
        eventRows: [
          value.eventRows[0]!,
          { ...value.eventRows[1]!, previous_event_sha256: `\\x${"f".repeat(64)}` }
        ]
      }),
      "previous_hash_mismatch",
      "2"
    );
    expectInvalid(
      verify(value, { eventBytes: component("audit:checkpoints", value.eventRows) }),
      "export_format_invalid"
    );
    expectInvalid(
      verify(value, { eventRows: [{ ...value.eventRows[0]!, unknown: true }] }),
      "export_format_invalid"
    );
  });

  it("detects organization, board, canonical-payload, projection, and hash drift", () => {
    const value = fixture();
    expectInvalid(
      verify(value, {
        eventRows: [{ ...value.eventRows[0]!, organization_id: id(700) }, value.eventRows[1]!]
      }),
      "event_scope_mismatch",
      "1"
    );

    const board = fixture(id(50));
    expectInvalid(
      verify(board, {
        eventRows: [{ ...board.eventRows[0]!, board_id: id(701) }, board.eventRows[1]!]
      }),
      "event_scope_mismatch",
      "1"
    );

    const projectionChanges: readonly Row[] = [
      { id: id(702) },
      { event_type: "vote_opened" },
      { actor_member_id: id(703) },
      { client_id: id(704) },
      { token_jti: id(705) },
      { object_type: "other_record" },
      { object_id: id(706) },
      { board_id: id(707) }
    ];
    for (const change of projectionChanges) {
      expectInvalid(
        verify(value, {
          eventRows: [{ ...value.eventRows[0]!, ...change }, value.eventRows[1]!]
        }),
        "event_hash_or_projection_mismatch",
        "1"
      );
    }
    expectInvalid(
      verify(value, {
        eventRows: [
          { ...value.eventRows[0]!, event_sha256: `\\x${"f".repeat(64)}` },
          value.eventRows[1]!
        ]
      }),
      "event_hash_or_projection_mismatch",
      "1"
    );

    const externalEntity = fixture(null, "external-record-2");
    expectInvalid(
      verify(externalEntity, {
        eventRows: [
          externalEntity.eventRows[0]!,
          { ...externalEntity.eventRows[1]!, object_id: id(708) }
        ]
      }),
      "event_hash_or_projection_mismatch",
      "2"
    );

    const noncanonical = Buffer.from(JSON.stringify(value.bodies[0]), "utf8");
    expect(noncanonical.equals(Buffer.from(canonicalJson(value.bodies[0]), "utf8"))).toBe(false);
    expectInvalid(
      verify(value, {
        eventRows: [
          {
            ...value.eventRows[0]!,
            canonical_payload: `\\x${noncanonical.toString("hex")}`
          },
          value.eventRows[1]!
        ]
      }),
      "export_format_invalid"
    );
  });

  it("distinguishes start, truncation, extension, audit-head range, and head-hash failures", () => {
    const value = fixture();
    expectInvalid(
      verify(value, {
        expectation: {
          ...value.expectation,
          rangeFirstSequence: "2",
          rangeLastSequence: "2"
        }
      }),
      "export_range_start_mismatch",
      "2"
    );
    expectInvalid(
      verify(value, {
        expectation: { ...value.expectation, rangeLastSequence: "4" }
      }),
      "export_range_end_mismatch",
      "3"
    );
    expectInvalid(
      verify(value, {
        expectation: { ...value.expectation, rangeLastSequence: "1" }
      }),
      "export_range_end_mismatch",
      "1"
    );
    expectInvalid(
      verify(value, {
        expectation: { ...value.expectation, auditHeadSequence: "1" }
      }),
      "export_range_exceeds_audit_head",
      "2"
    );
    expectInvalid(
      verify(value, {
        expectation: { ...value.expectation, auditHeadSha256: "f".repeat(64) }
      }),
      "exported_head_mismatch",
      "2"
    );
    expect(
      verify(value, {
        expectation: {
          ...value.expectation,
          auditHeadSequence: "3",
          auditHeadSha256: "f".repeat(64)
        }
      })
    ).toMatchObject({ valid: true, lastSequence: "2" });
  });
});

describe("offline audit-export checkpoint boundaries", () => {
  it("refuses a forged middle event concealed behind an unsigned redacted link", () => {
    const value = fixture(id(50));
    const third = appendEvent(value.events[1], body(3, id(50)));
    const checkpoint = signedCheckpointRow(value.privateKey, {
      ...value.checkpointPayload,
      lastSequence: "3",
      lastEventSha256: third.eventHash
    });
    const forged = appendEvent(value.events[0], {
      ...value.bodies[1],
      details: { suffix: "forged" }
    });
    expectInvalid(
      verify(value, {
        eventRows: [
          value.eventRows[0]!,
          exportedEventRow(forged),
          { ...redacted(exportedEventRow(third)), previous_event_sha256: `\\x${forged.eventHash}` }
        ],
        checkpointRows: [checkpoint.row],
        expectation: {
          ...value.expectation,
          rangeLastSequence: "3",
          auditHeadSequence: "3",
          auditHeadSha256: third.eventHash,
          latestCheckpointSha256: checkpoint.manifestSha256
        }
      }),
      "legacy_redacted_proof_unavailable"
    );
  });

  it("refuses a forged suffix after a signed start without a signed end", () => {
    const value = fixture();
    const third = appendEvent(value.events[1], body(3, null));
    const checkpoint = signedCheckpointRow(value.privateKey, {
      ...value.checkpointPayload,
      lastSequence: "3",
      lastEventSha256: third.eventHash
    });
    const forged = appendEvent(value.events[0], {
      ...value.bodies[1],
      details: { suffix: "forged" }
    });
    expectInvalid(
      verify(value, {
        eventRows: [value.eventRows[0]!, exportedEventRow(forged)],
        checkpointRows: [checkpoint.row],
        expectation: {
          ...value.expectation,
          auditHeadSequence: "3",
          auditHeadSha256: third.eventHash,
          latestCheckpointSha256: checkpoint.manifestSha256
        }
      }),
      "latest_checkpoint_does_not_anchor_export_end"
    );
  });

  it("binds every checkpoint projection, digest, signature, and exact trusted key", () => {
    const value = fixture();
    const projectionChanges: readonly Row[] = [
      { organization_id: id(800) },
      { id: id(801) },
      { first_sequence: "2" },
      { last_sequence: "1" },
      { first_event_sha256: `\\x${"f".repeat(64)}` },
      { last_event_sha256: `\\x${"f".repeat(64)}` },
      { signing_key_id: id(802) }
    ];
    for (const change of projectionChanges) {
      const row = { ...value.checkpointRow, ...change };
      expectInvalid(
        verify(value, { checkpointRows: [row] }),
        "checkpoint_signature_or_projection_mismatch",
        String(row["last_sequence"])
      );
    }

    expectInvalid(
      verify(value, {
        checkpointRows: [{ ...value.checkpointRow, manifest_sha256: `\\x${"f".repeat(64)}` }]
      }),
      "checkpoint_signature_or_projection_mismatch",
      "2"
    );
    expectInvalid(
      verify(value, {
        checkpointRows: [{ ...value.checkpointRow, signature: `\\x${"f".repeat(128)}` }]
      }),
      "checkpoint_signature_or_projection_mismatch",
      "2"
    );
    expectInvalid(
      verify(value, {
        trust: { ...value.trust, keys: [{ ...value.signingKey, id: id(803) }] }
      }),
      "checkpoint_signature_or_projection_mismatch",
      "2"
    );
    expectInvalid(
      verify(value, {
        trust: { ...value.trust, keys: [{ ...value.signingKey, kid: "other-key" }] }
      }),
      "checkpoint_signature_or_projection_mismatch",
      "2"
    );
    expectInvalid(
      verify(value, {
        trust: { ...value.trust, keys: [{ ...value.signingKey, public_jwk: {} }] }
      }),
      "export_format_invalid"
    );
  });

  it("rejects noncanonical or malformed checkpoint material and missing exact anchors", () => {
    const value = fixture();
    const manifest = Buffer.from(
      (value.checkpointRow["canonical_manifest"] as string).slice(2),
      "hex"
    );
    const noncanonical = Buffer.from(
      JSON.stringify(JSON.parse(manifest.toString("utf8")), null, 2),
      "utf8"
    );
    expect(noncanonical.equals(manifest)).toBe(false);
    expectInvalid(
      verify(value, {
        checkpointRows: [
          {
            ...value.checkpointRow,
            canonical_manifest: `\\x${noncanonical.toString("hex")}`
          }
        ]
      }),
      "export_format_invalid"
    );
    expectInvalid(
      verify(value, { checkpointRows: [{ ...value.checkpointRow, unknown: true }] }),
      "export_format_invalid"
    );
    expectInvalid(verify(value, { checkpointRows: [] }), "latest_trusted_checkpoint_unavailable");
    expectInvalid(
      verify(value, {
        expectation: { ...value.expectation, latestCheckpointSha256: "f".repeat(64) }
      }),
      "latest_trusted_checkpoint_unavailable"
    );
    expectInvalid(
      verify(value, { checkpointRows: [value.checkpointRow, value.checkpointRow] }),
      "duplicate_latest_trusted_checkpoint",
      "2"
    );
  });

  it("detects independently signed first and last checkpoint chain drift", () => {
    const value = fixture();
    for (const changes of [
      { firstEventSha256: "f".repeat(64) },
      { lastEventSha256: "f".repeat(64) }
    ] as const) {
      const replacement = signedCheckpointRow(value.privateKey, {
        ...value.checkpointPayload,
        ...changes,
        checkpointId: "firstEventSha256" in changes ? id(810) : id(811)
      });
      expectInvalid(
        verify(value, {
          checkpointRows: [replacement.row],
          expectation: {
            ...value.expectation,
            latestCheckpointSha256: replacement.manifestSha256
          }
        }),
        "checkpoint_chain_mismatch",
        "2"
      );
    }
  });

  it("anchors on either exported checkpoint edge and rejects a checkpoint wholly outside", () => {
    const value = fixture();
    expect(
      verify(value, {
        eventRows: [value.eventRows[0]!],
        expectation: {
          ...value.expectation,
          rangeFirstSequence: "1",
          rangeLastSequence: "1"
        }
      })
    ).toMatchObject({
      valid: true,
      eventCount: "1",
      anchorSequence: "1",
      latestCheckpointLastSequence: "2"
    });
    expect(
      verify(value, {
        eventRows: [value.eventRows[1]!],
        expectation: {
          ...value.expectation,
          rangeFirstSequence: "2",
          rangeLastSequence: "2"
        }
      })
    ).toMatchObject({ valid: true, eventCount: "1", anchorSequence: "2" });

    const outside = signedCheckpointRow(value.privateKey, {
      ...value.checkpointPayload,
      checkpointId: id(812),
      firstSequence: "3",
      lastSequence: "4",
      firstEventSha256: "a".repeat(64),
      lastEventSha256: "b".repeat(64)
    });
    expectInvalid(
      verify(value, {
        checkpointRows: [outside.row],
        expectation: {
          ...value.expectation,
          latestCheckpointSha256: outside.manifestSha256
        }
      }),
      "latest_checkpoint_outside_exported_range"
    );
  });
});

function attestedFixture() {
  const value = fixture(id(50));
  const events = component("audit:events", [redacted(value.eventRows[0]!), value.eventRows[1]!]);
  const checkpoints = component("audit:checkpoints", [value.checkpointRow]);
  const context = {
    exportRequestId: id(901),
    scopeSha256: "a".repeat(64),
    snapshotSha256: "b".repeat(64)
  };
  const signed = signAuditExportAttestation(
    {
      schemaVersion: "boardagent.audit-export-attestation.v1",
      instanceId: value.checkpointPayload.instanceId,
      ...context,
      organizationId,
      boardId: value.expectation.boardId,
      firstSequence: "1",
      lastSequence: "2",
      auditHeadSequence: "2",
      auditHeadSha256: value.expectation.auditHeadSha256,
      latestCheckpointSha256: value.expectation.latestCheckpointSha256,
      eventComponentSha256: sha256Hex(events),
      checkpointComponentSha256: sha256Hex(checkpoints),
      issuedAt: "2026-09-01T12:02:00Z",
      signingKeyId,
      keyId: value.signingKey.kid
    },
    value.privateKey
  );
  return { value, events, checkpoints, context: { ...context, signed } };
}

describe("exact signed audit export projection", () => {
  it("distinguishes an attested range from a latest checkpoint wholly outside that range", () => {
    const f = attestedFixture();
    const third = appendEvent(f.value.events[1], body(3, id(50)));
    const fourth = appendEvent(third, body(4, id(50)));
    const outside = signedCheckpointRow(f.value.privateKey, {
      ...f.value.checkpointPayload,
      checkpointId: id(903),
      firstSequence: "3",
      lastSequence: "4",
      firstEventSha256: third.eventHash,
      lastEventSha256: fourth.eventHash
    });
    const checkpoints = component("audit:checkpoints", [f.value.checkpointRow, outside.row]);
    const expectation = {
      ...f.value.expectation,
      auditHeadSequence: "4",
      auditHeadSha256: fourth.eventHash,
      latestCheckpointSha256: outside.manifestSha256
    };
    const signed = signAuditExportAttestation(
      {
        ...f.context.signed.payload,
        auditHeadSequence: "4",
        auditHeadSha256: fourth.eventHash,
        latestCheckpointSha256: outside.manifestSha256,
        checkpointComponentSha256: sha256Hex(checkpoints)
      },
      f.value.privateKey
    );
    expect(
      verifyOfflineAuditExport(f.events, checkpoints, expectation, f.value.trust, {
        ...f.context,
        signed
      })
    ).toMatchObject({
      valid: true,
      proof: "signed_export_snapshot",
      anchorSequence: null,
      attestedRangeLastSequence: "2",
      latestCheckpointLastSequence: "4",
      checkpointCount: 2
    });
  });

  it("verifies redacted bytes with an external trust anchor and refuses proof stripping", () => {
    const f = attestedFixture();
    expect(
      verifyOfflineAuditExport(
        f.events,
        f.checkpoints,
        f.value.expectation,
        f.value.trust,
        f.context
      )
    ).toMatchObject({ valid: true, proof: "signed_export_snapshot", eventCount: "2" });
    expectInvalid(
      verifyOfflineAuditExport(f.events, f.checkpoints, f.value.expectation, f.value.trust),
      "legacy_redacted_proof_unavailable"
    );
    expectInvalid(
      verifyOfflineAuditExport(
        f.events,
        f.checkpoints,
        f.value.expectation,
        {
          ...f.value.trust,
          keys: [
            {
              ...f.value.signingKey,
              public_jwk: generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" })
            }
          ]
        },
        f.context
      ),
      "export_attestation_signature_invalid"
    );
  });

  it("binds every expected scope, head, request and snapshot field", () => {
    const f = attestedFixture();
    const changes: readonly Partial<OfflineAuditExportExpectation>[] = [
      { organizationId: id(990) },
      { boardId: null },
      { rangeFirstSequence: "2" },
      { rangeLastSequence: "3" },
      { auditHeadSequence: "3" },
      { auditHeadSha256: "c".repeat(64) },
      { latestCheckpointSha256: "d".repeat(64) }
    ];
    for (const change of changes) {
      expectInvalid(
        verifyOfflineAuditExport(
          f.events,
          f.checkpoints,
          { ...f.value.expectation, ...change },
          f.value.trust,
          f.context
        ),
        "export_attestation_binding_mismatch"
      );
    }
    for (const change of [
      { exportRequestId: id(991) },
      { scopeSha256: "c".repeat(64) },
      { snapshotSha256: "d".repeat(64) }
    ]) {
      expectInvalid(
        verifyOfflineAuditExport(f.events, f.checkpoints, f.value.expectation, f.value.trust, {
          ...f.context,
          ...change
        }),
        "export_attestation_binding_mismatch"
      );
    }
  });

  it("refuses changed event bytes, checkpoint bytes, payloads and signatures", () => {
    const f = attestedFixture();
    for (const [events, checkpoints] of [
      [component("audit:events", f.value.eventRows), f.checkpoints],
      [f.events, component("audit:checkpoints", [])]
    ]) {
      expectInvalid(
        verifyOfflineAuditExport(
          events!,
          checkpoints!,
          f.value.expectation,
          f.value.trust,
          f.context
        ),
        "export_attestation_binding_mismatch"
      );
    }
    const bytes = Buffer.from(f.context.signed.signatureBase64Url, "base64url");
    bytes[0] = bytes[0]! ^ 1;
    for (const signed of [
      { ...f.context.signed, signatureBase64Url: bytes.toString("base64url") },
      {
        ...f.context.signed,
        payload: { ...f.context.signed.payload, issuedAt: "2026-09-01T12:03:00Z" }
      }
    ]) {
      expectInvalid(
        verifyOfflineAuditExport(f.events, f.checkpoints, f.value.expectation, f.value.trust, {
          ...f.context,
          signed
        }),
        "export_attestation_signature_invalid"
      );
    }
  });

  it("refuses cross-instance checkpoints even with a valid export signature", () => {
    const f = attestedFixture();
    const signed = signAuditExportAttestation(
      { ...f.context.signed.payload, instanceId: id(999) },
      f.value.privateKey
    );
    expectInvalid(
      verifyOfflineAuditExport(f.events, f.checkpoints, f.value.expectation, f.value.trust, {
        ...f.context,
        signed
      }),
      "checkpoint_instance_mismatch",
      "2"
    );
  });
});

function recoveryFixture() {
  const f = fixture();
  const third = appendEvent(f.events[1], body(3, null));
  const fourth = appendEvent(third, body(4, null));
  const events = [...f.events, third, fourth];
  const request: z.input<typeof AuditRecoveryRequestSchema> = {
    schemaVersion: "boardagent.audit-recovery-request.v1",
    recoveryId: id(2001),
    instanceId: f.checkpointPayload.instanceId,
    organizationId,
    firstSequence: "1",
    lastSequence: "4",
    firstEventSha256: events[0]!.eventHash,
    headSha256: fourth.eventHash,
    signingKeyId,
    keyId: f.signingKey.kid,
    firstUncoveredEventAt: events[0]!.occurredAt,
    preparedAt: "2026-09-01T12:30:01Z",
    expiresAt: "2026-09-01T13:00:01Z",
    operatorReference: "Synthetic offline recovery",
    reason: "Signing resumed after a synthetic outage"
  };
  const segment = (start: number, end: number, currentRequest = request) => {
    const first = events[start - 1]!,
      last = events[end - 1]!;
    const issuedAt = "2026-09-01T12:30:02Z";
    return signRecoveryCheckpoint(
      {
        ...f.checkpointPayload,
        schema: "boardagent.audit.recovery-checkpoint.v1",
        checkpointId: id(2010 + start),
        firstSequence: String(start),
        lastSequence: String(end),
        firstEventSha256: first.eventHash,
        lastEventSha256: last.eventHash,
        issuedAt,
        recovery: {
          request: currentRequest,
          requestSha256: canonicalSha256(currentRequest),
          firstCoveredEventAt: first.occurredAt,
          missedByMicroseconds: String(
            (Date.parse(issuedAt) - Date.parse(first.occurredAt) - 900_000) * 1000
          )
        }
      },
      f.privateKey
    );
  };
  const first = segment(1, 2),
    second = segment(3, 4);
  const row = (signed: SignedAuditRecoveryCheckpoint): Row => {
    const p = signed.payload,
      bytes = Buffer.from(canonicalJson(p));
    return {
      id: p.checkpointId,
      organization_id: p.organizationId,
      first_sequence: p.firstSequence,
      last_sequence: p.lastSequence,
      first_event_sha256: `\\x${p.firstEventSha256}`,
      last_event_sha256: `\\x${p.lastEventSha256}`,
      canonical_manifest: `\\x${bytes.toString("hex")}`,
      manifest_sha256: `\\x${sha256Hex(bytes)}`,
      signature: `\\x${Buffer.from(signed.signatureBase64Url, "base64url").toString("hex")}`,
      signing_key_id: p.signingKeyId,
      created_at: p.issuedAt
    };
  };
  const run = (
    options: {
      checkpoints?: readonly Row[];
      evidence?: readonly SignedAuditRecoveryCheckpoint[];
      contextEvidence?: readonly SignedAuditRecoveryCheckpoint[];
      latestCheckpointSha256?: string;
      omitContext?: boolean;
    } = {}
  ) => {
    const rows = options.checkpoints ?? [row(first), row(second)];
    const eventBytes = component("audit:events", events.map(exportedEventRow));
    const checkpointBytes = component("audit:checkpoints", rows);
    const last = rows.at(-1)!;
    const expectation = {
      ...f.expectation,
      rangeLastSequence: "4",
      auditHeadSequence: "4",
      auditHeadSha256: fourth.eventHash,
      latestCheckpointSha256:
        options.latestCheckpointSha256 ?? String(last.manifest_sha256).slice(2)
    };
    const evidence = options.evidence ?? [first];
    const context = {
      exportRequestId: id(2030),
      scopeSha256: "a".repeat(64),
      snapshotSha256: "b".repeat(64)
    };
    const signed = signAuditExportAttestation(
      {
        schemaVersion: "boardagent.audit-export-attestation.v2",
        instanceId: request.instanceId,
        ...context,
        organizationId,
        boardId: null,
        firstSequence: "1",
        lastSequence: "4",
        auditHeadSequence: "4",
        auditHeadSha256: fourth.eventHash,
        latestCheckpointSha256: expectation.latestCheckpointSha256,
        eventComponentSha256: sha256Hex(eventBytes),
        checkpointComponentSha256: sha256Hex(checkpointBytes),
        issuedAt: "2026-09-01T12:30:03Z",
        signingKeyId,
        keyId: request.keyId,
        auditRecoveryEvidence: [...evidence]
      },
      f.privateKey
    );
    return verifyOfflineAuditExport(
      eventBytes,
      checkpointBytes,
      expectation,
      f.trust,
      options.omitContext
        ? undefined
        : { ...context, signed, auditRecoveryEvidence: options.contextEvidence ?? evidence }
    );
  };
  return { f, request, first, second, row, segment, run, events };
}

describe("offline recovery evidence propagation", () => {
  it("verifies repeated segments of one signed request and returns the original warning", () => {
    const f = recoveryFixture();
    expect(f.run()).toMatchObject({
      valid: true,
      eventCount: "4",
      checkpointCount: 2,
      recoveryEvidence: [f.first],
      warnings: [`recovery:${f.request.recoveryId}:historical_checkpoint_deadline_missed`]
    });
    expectInvalid(f.run({ omitContext: true }), "export_recovery_evidence_binding_mismatch");
    expectInvalid(f.run({ contextEvidence: [] }), "export_recovery_evidence_binding_mismatch");
  });
  it("refuses a recovery whose signed request extends past the exported audit head", () => {
    const f = recoveryFixture();
    const request = { ...f.request, lastSequence: "5", headSha256: "a".repeat(64) };
    const first = f.segment(1, 2, request),
      second = f.segment(3, 4, request);
    expectInvalid(
      f.run({ checkpoints: [f.row(first), f.row(second)], evidence: [first] }),
      "recovery_request_scope_mismatch",
      "2"
    );
  });
  it("rejects conflicting request bytes under one recovery id even when every signature is valid", () => {
    const f = recoveryFixture();
    const second = f.segment(3, 4, { ...f.request, reason: "Different signed operator request" });
    expectInvalid(
      f.run({ checkpoints: [f.row(f.first), f.row(second)] }),
      "recovery_request_mismatch",
      "4"
    );
  });
  it("requires the first finding for every observed recovery and rejects substituted evidence", () => {
    const f = recoveryFixture();
    expectInvalid(
      f.run({ checkpoints: [f.row(f.second)] }),
      "export_recovery_evidence_binding_mismatch"
    );
    const unstarted = f.segment(3, 4, {
      ...f.request,
      recoveryId: id(2041),
      firstSequence: "2",
      firstEventSha256: f.events[1]!.eventHash,
      firstUncoveredEventAt: f.events[1]!.occurredAt
    });
    expectInvalid(
      f.run({ checkpoints: [f.row(f.first), f.row(unstarted)] }),
      "export_recovery_evidence_binding_mismatch"
    );
    const substituted = f.segment(1, 2, {
      ...f.request,
      reason: "Other valid signed first finding"
    });
    expectInvalid(f.run({ evidence: [substituted] }), "export_recovery_evidence_binding_mismatch");
  });
  it("preserves multiple independent recoveries in order", () => {
    const f = recoveryFixture();
    const first = f.segment(1, 2, {
      ...f.request,
      lastSequence: "2",
      headSha256: f.events[1]!.eventHash
    });
    const second = f.segment(3, 4, {
      ...f.request,
      recoveryId: id(2042),
      firstSequence: "3",
      firstEventSha256: f.events[2]!.eventHash,
      firstUncoveredEventAt: f.events[2]!.occurredAt
    });
    expect(
      f.run({ checkpoints: [f.row(first), f.row(second)], evidence: [first, second] })
    ).toMatchObject({
      valid: true,
      recoveryEvidence: [first, second],
      warnings: [
        `recovery:${first.payload.recovery.request.recoveryId}:historical_checkpoint_deadline_missed`,
        `recovery:${second.payload.recovery.request.recoveryId}:historical_checkpoint_deadline_missed`
      ]
    });
  });
  it("rejects a recovery signature mismatch and warnings unbacked by checkpoint rows", () => {
    const f = recoveryFixture();
    const bad = { ...f.first, signatureBase64Url: Buffer.alloc(64).toString("base64url") };
    expectInvalid(
      f.run({ checkpoints: [f.row(bad), f.row(f.second)] }),
      "checkpoint_signature_or_projection_mismatch",
      "2"
    );
    const ordinary = signedCheckpointRow(f.f.privateKey, {
      ...f.f.checkpointPayload,
      lastSequence: "4",
      lastEventSha256: f.events[3]!.eventHash
    });
    expectInvalid(
      f.run({ checkpoints: [ordinary.row] }),
      "export_recovery_evidence_binding_mismatch"
    );
  });
});

describe("independent checkpoint organization boundary", () => {
  it("refuses a valid legacy checkpoint signed for another organization", () => {
    const f = fixture();
    const other = signedCheckpointRow(f.privateKey, {
      ...f.checkpointPayload,
      organizationId: id(2999)
    });
    const actual = verify(f, {
      checkpointRows: [other.row],
      expectation: { ...f.expectation, latestCheckpointSha256: other.manifestSha256 }
    });
    expectInvalid(actual, "checkpoint_signature_or_projection_mismatch", "2");
  });
  it("refuses signed recovery evidence for another organization even with matching enclosing attestation", () => {
    const f = recoveryFixture();
    const request = { ...f.request, organizationId: id(2999) };
    const foreign = (value: SignedAuditRecoveryCheckpoint) =>
      signRecoveryCheckpoint(
        {
          ...value.payload,
          organizationId: request.organizationId,
          recovery: { ...value.payload.recovery, request, requestSha256: canonicalSha256(request) }
        },
        f.f.privateKey
      );
    const first = foreign(f.first),
      second = foreign(f.second);
    const rows = [first, second].map((value) => ({
      ...f.row(value),
      organization_id: organizationId
    }));
    expectInvalid(
      f.run({ checkpoints: rows, evidence: [first] }),
      "checkpoint_signature_or_projection_mismatch",
      "2"
    );
  });
});
