import { generateKeyPairSync } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  appendEvent,
  signCheckpoint,
  verifyOfflineAuditExport,
  type AuditEvent,
  type AuditEventBody
} from "../../lib/audit/src/index.js";
import { canonicalJson, sha256Hex, type JsonValue } from "../../lib/contracts/src/index.js";

const id = (suffix: number): string =>
  `018f0000-0000-7000-8000-${suffix.toString(16).padStart(12, "0")}`;
const organizationId = id(1);
const signingKeyId = id(2);

function body(suffix: number): AuditEventBody {
  return {
    eventId: id(100 + suffix),
    eventType: "context_read",
    actorMemberId: null,
    actorClientId: null,
    tokenJti: null,
    entityType: "test_record",
    entityId: id(200 + suffix),
    boardId: null,
    occurredAt: `2026-09-01T12:00:0${String(suffix)}Z`,
    origin: "mcp",
    details: { suffix },
    schemaVersion: 1
  };
}

function exportedEventRow(event: AuditEvent): Readonly<Record<string, JsonValue>> {
  const { sequence, previousHash, eventHash, ...eventBody } = event;
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
    object_id: event.entityId,
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

describe("offline exported audit verification", () => {
  it("detects projection mutation, truncation and the wrong external trust anchor", () => {
    const evidence = generateKeyPairSync("ed25519");
    const attacker = generateKeyPairSync("ed25519");
    const first = appendEvent(undefined, body(1));
    const second = appendEvent(first, body(2));
    const checkpoint = signCheckpoint(
      {
        schema: "boardagent.audit.checkpoint.v1",
        checkpointId: id(3),
        instanceId: id(4),
        organizationId,
        auditSchema: "boardagent.audit-event.v1",
        firstSequence: "1",
        lastSequence: "2",
        firstEventSha256: first.eventHash,
        lastEventSha256: second.eventHash,
        issuedAt: "2026-09-01T12:01:00Z",
        signingKeyId,
        keyId: "evidence-key-1"
      },
      evidence.privateKey
    );
    const manifestBytes = Buffer.from(canonicalJson(checkpoint.payload), "utf8");
    const manifestSha256 = sha256Hex(manifestBytes);
    const eventRows = [exportedEventRow(first), exportedEventRow(second)];
    const checkpointRows: JsonValue[] = [
      {
        id: checkpoint.payload.checkpointId,
        organization_id: organizationId,
        first_sequence: checkpoint.payload.firstSequence,
        last_sequence: checkpoint.payload.lastSequence,
        first_event_sha256: `\\x${checkpoint.payload.firstEventSha256}`,
        last_event_sha256: `\\x${checkpoint.payload.lastEventSha256}`,
        canonical_manifest: `\\x${manifestBytes.toString("hex")}`,
        manifest_sha256: `\\x${manifestSha256}`,
        signature: `\\x${Buffer.from(checkpoint.signatureBase64Url, "base64url").toString("hex")}`,
        signing_key_id: signingKeyId,
        created_at: "2026-09-01 12:01:00+00"
      }
    ];
    const expectation = {
      organizationId,
      boardId: null,
      rangeFirstSequence: "1",
      rangeLastSequence: "2",
      auditHeadSequence: "2",
      auditHeadSha256: second.eventHash,
      latestCheckpointSha256: manifestSha256
    } as const;
    const trust = (public_jwk: JsonValue) => ({
      schema_version: "boardagent.trusted-evidence-keys.v1",
      keys: [
        {
          id: signingKeyId,
          kid: "evidence-key-1",
          algorithm: "EdDSA",
          public_jwk
        }
      ]
    });
    const trusted = trust(evidence.publicKey.export({ format: "jwk" }) as JsonValue);

    expect(
      verifyOfflineAuditExport(
        component("audit:events", eventRows),
        component("audit:checkpoints", checkpointRows),
        expectation,
        trusted
      )
    ).toEqual({
      valid: true,
      eventCount: "2",
      firstSequence: "1",
      lastSequence: "2",
      headHash: second.eventHash,
      checkpointCount: 1,
      anchorSequence: "2",
      latestCheckpointLastSequence: "2"
    });

    const mutatedRows = [
      eventRows[0]!,
      { ...(eventRows[1] as Readonly<Record<string, JsonValue>>), object_type: "other_record" }
    ];
    expect(
      verifyOfflineAuditExport(
        component("audit:events", mutatedRows),
        component("audit:checkpoints", checkpointRows),
        expectation,
        trusted
      )
    ).toMatchObject({
      valid: false,
      firstBreakSequence: "2",
      reason: "event_hash_or_projection_mismatch"
    });
    expect(
      verifyOfflineAuditExport(
        component("audit:events", eventRows.slice(0, 1)),
        component("audit:checkpoints", checkpointRows),
        expectation,
        trusted
      )
    ).toMatchObject({
      valid: false,
      firstBreakSequence: "2",
      reason: "export_range_end_mismatch"
    });
    expect(
      verifyOfflineAuditExport(
        component("audit:events", eventRows),
        component("audit:checkpoints", checkpointRows),
        expectation,
        trust(attacker.publicKey.export({ format: "jwk" }) as JsonValue)
      )
    ).toMatchObject({
      valid: false,
      firstBreakSequence: "2",
      reason: "checkpoint_signature_or_projection_mismatch"
    });
  });
});
