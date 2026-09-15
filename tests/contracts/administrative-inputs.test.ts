import { describe, expect, it } from "vitest";
import {
  toolInputSchema,
  TOOL_INPUT_SCHEMA_VERSION
} from "../../lib/contracts/src/surface-inputs.js";

const ID = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e0f";
const base = {
  schema_version: TOOL_INPUT_SCHEMA_VERSION,
  idempotency_key: "administrative-input-0001"
};
const citation = {
  document_version_id: ID,
  sha256: "a".repeat(64),
  clause: "Appointment",
  locator: "section 1"
};

describe("AC27 administrative action input boundaries", () => {
  it("accepts each exact administrator operation and rejects mixed or unversioned actions", () => {
    const schema = toolInputSchema("manage_company_admin");
    for (const operation of ["grant", "transfer"] as const) {
      const change = {
        operation,
        proposal_id: ID,
        member_id: ID,
        expected_member_version: 1,
        reason: "Appointed"
      };
      expect(schema.parse({ ...base, change })).toEqual({ ...base, change });
      expect(
        schema.safeParse({ ...base, change: { ...change, expires_at: "2026-10-01T00:00:00Z" } })
          .success
      ).toBe(false);
    }
    for (const operation of ["accept", "decline", "cancel"] as const) {
      const change = {
        operation,
        proposal_id: ID,
        expected_proposal_version: 1,
        reason: "Reviewed"
      };
      expect(schema.parse({ ...base, change })).toEqual({ ...base, change });
      expect(schema.safeParse({ ...base, change: { ...change, member_id: ID } }).success).toBe(
        false
      );
    }
    const change = {
      operation: "revoke",
      assignment_id: ID,
      member_id: ID,
      expected_member_version: 1,
      reason: "Appointment ended"
    };
    expect(schema.parse({ ...base, change })).toEqual({ ...base, change });
    for (const patch of [
      { expected_member_version: 0 },
      { expected_member_version: Number.MAX_SAFE_INTEGER + 1 },
      { reason: "x".repeat(2001) },
      { reason: "" },
      { reason: "Line\r\nbreak" }
    ]) {
      expect(schema.safeParse({ ...base, change: { ...change, ...patch } }).success).toBe(false);
    }
    expect(schema.safeParse({ ...base, change, hidden: true }).success).toBe(false);
  });

  it("bounds and binds delegation evidence with strict nested fields", () => {
    const schema = toolInputSchema("manage_member_admin_delegation");
    const change = {
      operation: "grant",
      delegation_id: ID,
      member_id: ID,
      board_id: ID,
      expected_member_version: 1,
      expires_at: "2026-10-01T00:00:00Z",
      reason: "Board appointment",
      authority_evidence: [citation]
    };
    expect(schema.parse({ ...base, change })).toEqual({ ...base, change });
    for (const authority_evidence of [
      [],
      [citation, citation],
      Array.from({ length: 9 }, (_, i) => ({ ...citation, locator: String(i) })),
      [{ ...citation, secret: "injection" }]
    ]) {
      expect(schema.safeParse({ ...base, change: { ...change, authority_evidence } }).success).toBe(
        false
      );
    }
    expect(schema.safeParse({ ...base, change: { ...change, board_id: null } }).success).toBe(
      false
    );
    const revoke = {
      operation: "revoke",
      delegation_id: ID,
      board_id: ID,
      expected_delegation_version: 1,
      reason: "Ended"
    };
    expect(schema.parse({ ...base, change: revoke })).toEqual({ ...base, change: revoke });
    expect(schema.safeParse({ ...base, change: { ...revoke, member_id: ID } }).success).toBe(false);
  });

  it("defaults administrative reads to own access and limits discovery to 100 entries", () => {
    const schema = toolInputSchema("list_administrative_access");
    expect(schema.parse({ schema_version: TOOL_INPUT_SCHEMA_VERSION })).toEqual({
      schema_version: TOOL_INPUT_SCHEMA_VERSION,
      mode: "mine",
      board_id: null,
      limit: 50,
      cursor: null
    });
    for (const patch of [
      { limit: 101 },
      { limit: 0 },
      { cursor: "x".repeat(4097) },
      { member_id: ID },
      { mode: "all" },
      { idempotency_key: base.idempotency_key }
    ]) {
      expect(
        schema.safeParse({ schema_version: TOOL_INPUT_SCHEMA_VERSION, ...patch }).success
      ).toBe(false);
    }
  });

  it("preserves old member inputs byte-for-byte while accepting exact optional cited basis", () => {
    const schema = toolInputSchema("manage_member");
    const change = {
      operation: "invite",
      member_id: ID,
      board_id: ID,
      member_kind: "human",
      seat_role: "voting_member",
      legal_name: "Test Director",
      display_name: "Test Director",
      voting_weight: 1,
      accountable_principal_id: null
    };
    expect(schema.parse({ ...base, change })).toEqual({ ...base, change });
    const cited = {
      ...base,
      change: { ...change, reason: "Appointment" },
      authority_evidence: [citation]
    };
    expect(schema.parse(cited)).toEqual(cited);
    expect(schema.safeParse({ ...cited, authority_evidence: [citation, citation] }).success).toBe(
      false
    );
  });
});
