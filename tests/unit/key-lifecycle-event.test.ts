import { describe, expect, it } from "vitest";
import { AuditEventBodySchema } from "../../lib/audit/src/event.js";
import { appendEvent, verifyChain } from "../../lib/audit/src/event.js";
import {
  KeyLifecycleChangedSchema,
  KeyLifecycleStateSchema
} from "../../lib/audit/src/key-lifecycle-event.js";
import type { z } from "zod";

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, "0")}`;
type Details = z.input<typeof KeyLifecycleChangedSchema>;
const recordedAt = "2026-09-09T00:00:00.000000Z";
function details(
  purpose: Details["purpose"] = "evidence_signing",
  operation: Details["operation"] = "replace"
): Details {
  const algorithm = (
    {
      oauth_signing: "ES256",
      evidence_signing: "EdDSA",
      browser_session: "HMAC-SHA256",
      data_kek: "A256GCM",
      backup_kek: "A256GCM"
    } as const
  )[purpose];
  const before: z.input<typeof KeyLifecycleStateSchema> = {
    keyId: id(3),
    kid: "synthetic-prior",
    algorithm,
    publicMaterialSha256:
      purpose === "oauth_signing" || purpose === "evidence_signing" ? "a".repeat(64) : null,
    activatedAt: "2026-09-01T00:00:00.000000Z",
    retiredAt: null,
    compromisedAt: null
  };
  const after = { ...before };
  if (operation === "mark_compromised") after.compromisedAt = "2026-09-08T00:00:00.000001Z";
  else after.retiredAt = recordedAt;
  return {
    schemaVersion: "boardagent.key-lifecycle-changed.v1",
    operationId: id(2),
    requestSha256: "1".repeat(64),
    instanceId: id(4),
    organizationId: id(5),
    purpose,
    operation,
    before,
    after,
    replacement:
      operation === "replace"
        ? {
            ...before,
            keyId: id(6),
            kid: "synthetic-next",
            activatedAt: recordedAt,
            publicMaterialSha256: before.publicMaterialSha256 === null ? null : "b".repeat(64)
          }
        : null,
    recordedAt,
    declaredCompromisedAt: operation === "mark_compromised" ? after.compromisedAt : null,
    dependencyStateSha256: "2".repeat(64),
    retainedMaterialSha256: "3".repeat(64),
    operatorReference: "Synthetic operator ticket",
    reason: "Scheduled synthetic key replacement",
    effects: {
      revokedSessions: "0",
      revokedRefreshFamilies: "0",
      cancelledStages: "0",
      affectedTotp: "0",
      disabledWebhooks: "0",
      rewrappedWebhooks: "0"
    }
  };
}
function event(evidence = details()) {
  return {
    eventId: id(1),
    eventType: "key_lifecycle_changed" as const,
    actorMemberId: null,
    actorClientId: null,
    tokenJti: null,
    boardId: null,
    origin: "cli",
    entityType: "key_lifecycle_operation",
    entityId: id(2),
    occurredAt: recordedAt,
    schemaVersion: 1 as const,
    details: evidence
  };
}

describe("operator key lifecycle evidence", () => {
  it("refuses a lifecycle event with no exact operation and before/after evidence", () => {
    expect(
      AuditEventBodySchema.safeParse({
        eventId: id(1),
        eventType: "key_lifecycle_changed",
        actorMemberId: null,
        actorClientId: null,
        tokenJti: null,
        boardId: null,
        origin: "cli",
        entityType: "key_lifecycle_operation",
        entityId: id(2),
        occurredAt: "2026-09-09T00:00:00.000000Z",
        schemaVersion: 1,
        details: { reason: "A bare claim that a key changed" }
      }).success
    ).toBe(false);
  });

  it("accepts the exact before/after fact for each purpose and operation, without altering it", () => {
    for (const purpose of [
      "oauth_signing",
      "evidence_signing",
      "browser_session",
      "data_kek",
      "backup_kek"
    ] as const) {
      for (const operation of ["replace", "retire", "mark_compromised"] as const) {
        const evidence = details(purpose, operation);
        expect(KeyLifecycleChangedSchema.parse(evidence)).toEqual(evidence);
        expect(AuditEventBodySchema.parse(event(evidence))).toEqual(event(evidence));
      }
    }
  });

  it("permits replacement after retirement or compromise while keeping the original warning times", () => {
    const evidence = details();
    evidence.before.retiredAt = "2026-09-08T12:00:00.000000Z";
    evidence.before.compromisedAt = "2026-09-08T00:00:00.000001Z";
    evidence.after = { ...evidence.before };
    expect(KeyLifecycleChangedSchema.parse(evidence).after).toEqual(evidence.before);
    evidence.after.compromisedAt = null;
    expect(KeyLifecycleChangedSchema.safeParse(evidence).success).toBe(false);
  });

  it("preserves microsecond compromise bounds and allows only an earlier newly declared warning", () => {
    const evidence = details("evidence_signing", "mark_compromised");
    evidence.before.compromisedAt = "2026-09-08T00:00:00.000002Z";
    expect(KeyLifecycleChangedSchema.safeParse(evidence).success).toBe(true);
    for (const declared of [
      "2026-09-08T00:00:00.000002Z",
      "2026-09-08T00:00:00.000003Z",
      "2026-08-31T23:59:59.999999Z",
      "2026-09-09T00:00:00.000001Z"
    ]) {
      expect(
        KeyLifecycleChangedSchema.safeParse({
          ...evidence,
          declaredCompromisedAt: declared,
          after: { ...evidence.after, compromisedAt: declared }
        }).success
      ).toBe(false);
    }
  });

  it("rejects changed identity, algorithm, public material, chronology and unsupported effect counts", () => {
    const invalid: Array<(v: Details) => void> = [
      (v) => {
        v.after.keyId = id(9);
      },
      (v) => {
        v.after.kid = "other";
      },
      (v) => {
        v.after.publicMaterialSha256 = "c".repeat(64);
      },
      (v) => {
        v.before.algorithm = "ES256";
        v.after.algorithm = "ES256";
      },
      (v) => {
        v.after.retiredAt = "2026-09-08T00:00:00.000000Z";
      },
      (v) => {
        v.before.activatedAt = "2026-09-09T00:00:00.000001Z";
      },
      (v) => {
        v.replacement!.activatedAt = "2026-09-08T00:00:00.000000Z";
      },
      (v) => {
        v.replacement!.keyId = v.before.keyId;
      },
      (v) => {
        v.replacement!.kid = v.before.kid;
      },
      (v) => {
        v.replacement!.publicMaterialSha256 = v.before.publicMaterialSha256;
      },
      (v) => {
        v.replacement!.compromisedAt = recordedAt;
      },
      (v) => {
        v.replacement = null;
      },
      (v) => {
        v.declaredCompromisedAt = recordedAt;
      },
      (v) => {
        v.effects.affectedTotp = "1";
      },
      (v) => {
        v.effects.revokedSessions = "1000001";
      },
      (v) => {
        v.effects.cancelledStages = "01";
      },
      (v) => {
        v.reason = "   ";
      },
      (v) => {
        v.reason = "x\u0000y";
      },
      (v) => {
        v.operatorReference = "e\u0301";
      }
    ];
    for (const change of invalid) {
      const evidence = details();
      change(evidence);
      expect(KeyLifecycleChangedSchema.safeParse(evidence).success).toBe(false);
    }
    expect(
      KeyLifecycleChangedSchema.safeParse({ ...details(), privateKey: "synthetic-secret" }).success
    ).toBe(false);
    expect(
      KeyLifecycleChangedSchema.safeParse({
        ...details(),
        before: { ...details().before, d: "synthetic-secret" }
      }).success
    ).toBe(false);
    const symmetric = details("data_kek");
    symmetric.before.publicMaterialSha256 = "c".repeat(64);
    expect(KeyLifecycleChangedSchema.safeParse(symmetric).success).toBe(false);
  });

  it("requires the matching operator origin, operation ID, transaction time and absent human principal", () => {
    for (const changes of [
      { origin: "mcp" },
      { actorMemberId: id(7) },
      { actorClientId: id(8) },
      { tokenJti: id(9) },
      { boardId: id(10) },
      { entityType: "key" },
      { entityId: id(11) },
      { occurredAt: "2026-09-09T00:00:00.000001Z" }
    ])
      expect(AuditEventBodySchema.safeParse({ ...event(), ...changes }).success).toBe(false);
  });

  it("includes the full lifecycle fact in chain verification and catches changed warning evidence", () => {
    const source = event(details("evidence_signing", "mark_compromised"));
    const appended = appendEvent(undefined, source);
    expect(verifyChain([appended]).valid).toBe(true);
    const altered = {
      ...appended,
      details: { ...source.details, reason: "Changed after the audit event" }
    };
    expect(verifyChain([altered])).toMatchObject({ valid: false, reason: "event_hash_mismatch" });
  });
});

describe("key lifecycle independent boundary cases", () => {
  const issue = (value: Details) => {
    const result = KeyLifecycleChangedSchema.safeParse(value);
    expect(result.success).toBe(false);
    if (!result.success)
      expect(result.error.issues).toContainEqual(
        expect.objectContaining({ code: "custom", message: "inconsistent key lifecycle evidence" })
      );
  };
  it("preserves public coordinates while ignoring labels", async () => {
    const { keyLifecyclePublicMaterialSha256 } =
      await import("../../lib/audit/src/key-lifecycle-event.js");
    const { canonicalSha256 } = await import("../../lib/contracts/src/index.js");
    for (const key of [
      { kty: "EC", crv: "P-256", x: "public-x", y: "public-y" },
      { kty: "OKP", crv: "Ed25519", x: "public-x" }
    ] as const) {
      const labelled = { ...key, kid: "label" };
      expect(keyLifecyclePublicMaterialSha256(labelled)).toBe(canonicalSha256(key));
    }
  });
  it("enforces individual state chronology and permits simultaneous activation and retirement or compromise", () => {
    const state = details().before;
    for (const field of ["retiredAt", "compromisedAt"] as const) {
      expect(KeyLifecycleStateSchema.parse({ ...state, [field]: state.activatedAt })[field]).toBe(
        state.activatedAt
      );
      const result = KeyLifecycleStateSchema.safeParse({
        ...state,
        [field]: "2026-08-31T23:59:59.999999Z"
      });
      expect(result.success).toBe(false);
      if (!result.success)
        expect(result.error.issues).toContainEqual(
          expect.objectContaining({ code: "custom", message: "invalid key-state time ordering" })
        );
    }
  });
  it("accepts the count ceiling, forbids ambiguous labels and rejects noncanonical operator text", () => {
    for (const count of ["0", "1", "10", "1000000"]) {
      const value = details();
      value.effects.cancelledStages = count;
      expect(KeyLifecycleChangedSchema.parse(value).effects.cancelledStages).toBe(count);
    }
    for (const count of ["1000001", "01", "1a", "-1", "1\n"]) {
      const value = details();
      value.effects.cancelledStages = count;
      expect(() => KeyLifecycleChangedSchema.parse(value)).toThrow();
    }
    for (const text of [
      " padded",
      "padded ",
      "e\u0301",
      "x\u001fy",
      "x\u007fy",
      "x\u0080y",
      "x\u009fy",
      "x\ud800y"
    ]) {
      for (const field of ["reason", "operatorReference"] as const) {
        expect(KeyLifecycleChangedSchema.safeParse({ ...details(), [field]: text }).success).toBe(
          false
        );
      }
    }
    expect(KeyLifecycleChangedSchema.parse({ ...details(), reason: "ok ~ ¡" }).reason).toBe(
      "ok ~ ¡"
    );
    for (const kid of ["!key", "key!"])
      expect(KeyLifecycleStateSchema.safeParse({ ...details().before, kid }).success).toBe(false);
  });
  it("binds each state's material and chronology independently of before/after equality", () => {
    for (const field of ["activatedAt", "retiredAt", "compromisedAt"] as const) {
      const value = details();
      value.before[field] = "2026-09-10T00:00:00.000000Z";
      value.after = { ...value.before, retiredAt: value.before.retiredAt ?? recordedAt };
      if (field === "activatedAt") value.after.retiredAt = "2026-09-10T00:00:00.000000Z";
      issue(value);
    }
    const alreadyCompromised = details();
    alreadyCompromised.before.compromisedAt = recordedAt;
    alreadyCompromised.after.compromisedAt = recordedAt;
    expect(KeyLifecycleChangedSchema.parse(alreadyCompromised)).toEqual(alreadyCompromised);
    for (const purpose of ["oauth_signing", "browser_session"] as const) {
      const value = details(purpose);
      value.before.publicMaterialSha256 = purpose === "oauth_signing" ? null : "a".repeat(64);
      value.after.publicMaterialSha256 = value.before.publicMaterialSha256;
      value.replacement!.publicMaterialSha256 = purpose === "oauth_signing" ? null : "b".repeat(64);
      issue(value);
    }
    const replacement = details();
    replacement.replacement!.algorithm = "ES256";
    issue(replacement);
  });
  it("forbids repeated retirement and unexpected replacements; binds compromise at both time endpoints", () => {
    const repeat = details("evidence_signing", "retire");
    repeat.before.retiredAt = recordedAt;
    repeat.after = { ...repeat.before };
    issue(repeat);
    for (const operation of ["retire", "mark_compromised"] as const) {
      const value = details("evidence_signing", operation);
      value.replacement = details().replacement;
      issue(value);
    }
    const retiredReplacement = details();
    retiredReplacement.replacement!.retiredAt = recordedAt;
    issue(retiredReplacement);
    const missing = details("evidence_signing", "mark_compromised");
    missing.declaredCompromisedAt = null;
    missing.after.compromisedAt = null;
    issue(missing);
    for (const instant of [details().before.activatedAt, recordedAt]) {
      const value = details("evidence_signing", "mark_compromised");
      value.declaredCompromisedAt = instant;
      value.after.compromisedAt = instant;
      expect(KeyLifecycleChangedSchema.parse(value)).toEqual(value);
    }
    for (const field of ["disabledWebhooks", "rewrappedWebhooks"] as const) {
      const value = details();
      value.effects[field] = "1";
      issue(value);
    }
    const data = details("data_kek");
    data.effects.affectedTotp = "10";
    data.effects.disabledWebhooks = "1";
    data.effects.rewrappedWebhooks = "1";
    expect(KeyLifecycleChangedSchema.parse(data)).toEqual(data);
    for (const operation of ["retire", "mark_compromised"] as const) {
      const value = details("data_kek", operation);
      value.effects.rewrappedWebhooks = "1";
      issue(value);
    }
  });
});

it("requires six-digit lifecycle timestamps and attributable outer event errors", () => {
  for (const activatedAt of [
    "2026-09-01T00:00:00Z",
    "2026-09-01T00:00:00.1Z",
    "2026-09-01T00:00:00.00000Z"
  ])
    expect(KeyLifecycleStateSchema.safeParse({ ...details().before, activatedAt }).success).toBe(
      false
    );
  const result = AuditEventBodySchema.safeParse({ ...event(), origin: "mcp" });
  expect(result.success).toBe(false);
  if (!result.success)
    expect(result.error.issues).toContainEqual(
      expect.objectContaining({ code: "custom", message: "invalid operator key lifecycle event" })
    );
});
