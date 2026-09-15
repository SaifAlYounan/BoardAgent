import { describe, expect, it } from "vitest";

import {
  OfflineAuditCheckpointRowSchema,
  OfflineAuditExportExpectationSchema,
  OfflineExportComponentSchema,
  OfflineFullAuditEventRowSchema,
  OfflinePgBytesSchema,
  OfflinePgSha256Schema,
  OfflinePgSignatureSchema,
  OfflinePositiveDecimalSchema,
  OfflineRedactedAuditEventRowSchema,
  parseOfflineCanonicalJson,
  parseOfflineExportComponent
} from "../../lib/audit/src/index.js";
import { canonicalJson, type JsonValue } from "../../lib/contracts/src/index.js";

const id = (suffix: number): string =>
  `018f0000-0000-7000-8000-${suffix.toString(16).padStart(12, "0")}`;
const pgHash = (character = "a"): string => `\\x${character.repeat(64)}`;

const fullRow = {
  id: id(1),
  sequence: "1",
  organization_id: id(2),
  board_id: null,
  event_type: "context_read",
  schema_version: "boardagent.audit-event.v1" as const,
  actor_member_id: null,
  acting_for_member_id: null,
  client_id: null,
  token_jti: null,
  consent_record_id: null,
  object_type: "test_record",
  object_id: id(3),
  object_version: null,
  canonical_payload: "\\x7b7d",
  previous_event_sha256: pgHash("0"),
  event_sha256: pgHash("1"),
  occurred_at: "2026-09-01 12:00:00+00"
};

const checkpointRow = {
  id: id(4),
  organization_id: id(2),
  first_sequence: "1",
  last_sequence: "1",
  first_event_sha256: pgHash("1"),
  last_event_sha256: pgHash("1"),
  canonical_manifest: "\\x7b7d",
  manifest_sha256: pgHash("2"),
  signature: `\\x${"3".repeat(128)}`,
  signing_key_id: id(5),
  created_at: "2026-09-01 12:01:00+00"
};

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

describe("offline export wire-format boundaries", () => {
  it("anchors every decimal and PostgreSQL text encoding at both ends", () => {
    for (const value of ["1", "10", "999999"]) {
      expect(OfflinePositiveDecimalSchema.parse(value)).toBe(value);
    }
    for (const value of ["0", "01", "x1", "1x", "1a", "-1", ""]) {
      expect(OfflinePositiveDecimalSchema.safeParse(value).success).toBe(false);
    }

    const sha = pgHash();
    expect(OfflinePgSha256Schema.parse(sha)).toBe(sha);
    for (const value of [`!${sha}`, `${sha}!`, `\\x${"A".repeat(64)}`]) {
      expect(OfflinePgSha256Schema.safeParse(value).success).toBe(false);
    }

    for (const value of ["\\x00", "\\x7b7d", `\\x${"a0".repeat(128)}`]) {
      expect(OfflinePgBytesSchema.parse(value)).toBe(value);
    }
    for (const value of ["!\\x00", "\\x00!", "\\x0", "\\x", "\\xGG"]) {
      expect(OfflinePgBytesSchema.safeParse(value).success).toBe(false);
    }

    const signature = `\\x${"a".repeat(128)}`;
    expect(OfflinePgSignatureSchema.parse(signature)).toBe(signature);
    for (const value of [`!${signature}`, `${signature}!`, `\\x${"a".repeat(126)}`]) {
      expect(OfflinePgSignatureSchema.safeParse(value).success).toBe(false);
    }
  });

  it("accepts exact full, redacted, checkpoint, and component rows and rejects edge drift", () => {
    expect(OfflineFullAuditEventRowSchema.parse(fullRow)).toEqual(fullRow);
    for (const object_type of [`!${fullRow.object_type}`, `${fullRow.object_type}!`]) {
      expect(OfflineFullAuditEventRowSchema.safeParse({ ...fullRow, object_type }).success).toBe(
        false
      );
    }

    const redacted = {
      sequence: "1",
      previous_event_sha256: pgHash("0"),
      event_sha256: pgHash("1"),
      redacted: "true" as const
    };
    expect(OfflineRedactedAuditEventRowSchema.parse(redacted)).toEqual(redacted);
    expect(
      OfflineRedactedAuditEventRowSchema.safeParse({ ...redacted, redacted: "false" }).success
    ).toBe(false);
    expect(OfflineAuditCheckpointRowSchema.parse(checkpointRow)).toEqual(checkpointRow);

    const exactComponent = {
      schemaVersion: "boardagent.export-component.v1" as const,
      name: "audit:events",
      rowEncoding: "postgres-text-v1" as const,
      rows: []
    };
    expect(OfflineExportComponentSchema.parse(exactComponent)).toEqual(exactComponent);
    for (const name of [`!${exactComponent.name}`, `${exactComponent.name}!`]) {
      expect(OfflineExportComponentSchema.safeParse({ ...exactComponent, name }).success).toBe(
        false
      );
    }
  });

  it("parses only fatal UTF-8, canonical bytes, and the exact requested component", () => {
    const bytes = component("audit:events", ["marker"]);
    expect(parseOfflineCanonicalJson(bytes)).toEqual(JSON.parse(bytes.toString("utf8")));
    expect(parseOfflineExportComponent(bytes, "audit:events")).toEqual({
      schemaVersion: "boardagent.export-component.v1",
      name: "audit:events",
      rowEncoding: "postgres-text-v1",
      rows: ["marker"]
    });
    expect(() => parseOfflineExportComponent(bytes, "audit:checkpoints")).toThrow(
      "export component is not the expected canonical byte sequence"
    );
    expect(() =>
      parseOfflineExportComponent(
        Buffer.from(JSON.stringify(JSON.parse(bytes.toString("utf8")), null, 2), "utf8"),
        "audit:events"
      )
    ).toThrow("offline JSON is not canonical UTF-8");

    const invalidUtf8 = Buffer.from(bytes);
    const marker = invalidUtf8.indexOf(Buffer.from("marker", "utf8"));
    if (marker < 0) throw new Error("fixture marker missing");
    invalidUtf8[marker] = 0xff;
    expect(() => parseOfflineCanonicalJson(invalidUtf8)).toThrow(TypeError);
  });

  it("requires an exact non-inverted expectation, including an anchored audit head", () => {
    const expectation = {
      organizationId: id(10),
      boardId: null,
      rangeFirstSequence: "2",
      rangeLastSequence: "2",
      auditHeadSequence: "2",
      auditHeadSha256: "a".repeat(64),
      latestCheckpointSha256: "b".repeat(64)
    };
    expect(OfflineAuditExportExpectationSchema.parse(expectation)).toEqual(expectation);
    for (const auditHeadSequence of ["x2", "2x", "2a", "01", "-1"]) {
      expect(
        OfflineAuditExportExpectationSchema.safeParse({ ...expectation, auditHeadSequence }).success
      ).toBe(false);
    }
    const inverted = OfflineAuditExportExpectationSchema.safeParse({
      ...expectation,
      rangeFirstSequence: "3"
    });
    expect(inverted.success).toBe(false);
    if (inverted.success) throw new Error("expected inverted range failure");
    expect(inverted.error.issues[0]?.message).toBe(
      "expected audit export sequence range is inverted"
    );
    expect(
      OfflineAuditExportExpectationSchema.safeParse({ ...expectation, extra: true }).success
    ).toBe(false);
  });
});
