import { readFile } from "node:fs/promises";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  HUMAN_ACCEPTANCE_RECEIPT_PATH,
  HumanAcceptanceReceiptSchema,
  REQUIRED_HUMAN_ACTIONS,
  verifyHumanAcceptanceReceipt
} from "../../scripts/src/human-acceptance-evidence.js";
import { testId } from "../helpers/authorized-actor.js";

const CANDIDATE = {
  gitCommit: "f1c96da000000000000000000000000000000000",
  sourceTreeSha256: "a".repeat(64)
};

/** A complete synthetic receipt. It proves the schema, never SR-102. */
function syntheticReceipt() {
  const members = [
    { role: "company_admin", displayName: "Company administrator", votingWeight: 0 },
    { role: "secretary", displayName: "Rowan Ash", votingWeight: 0 },
    { role: "chair", displayName: "Mira Vale", votingWeight: 1 },
    { role: "director", displayName: "Tomas Reed", votingWeight: 1 },
    { role: "director", displayName: "Leila Stone", votingWeight: 1 }
  ] as const;
  const base = Date.parse("2026-09-20T08:00:00.000Z");
  return {
    schemaVersion: "boardagent.human-acceptance-receipt.v1",
    recordedAt: "2026-09-21T18:00:00.000Z",
    candidate: { ...CANDIDATE },
    instance: { publicBaseUrl: "https://localhost/", schemaVersion: 170 },
    client: { name: "Claude Code", version: "2.1.270" },
    person: {
      displayName: "Test Administrator",
      statement:
        "I activated the first account with my own passkey, enrolled the four Mining roles, restarted one lapsed activation, recovered one passkey and ran the full cycle.",
      passkeyAuthenticator: "Touch ID on the build Mac"
    },
    members: members.map((member, index) => ({
      memberId: testId(900_000 + index),
      displayName: member.displayName,
      role: member.role,
      votingWeight: member.votingWeight,
      activatedAt: new Date(base + index * 60_000).toISOString()
    })),
    actions: REQUIRED_HUMAN_ACTIONS.map((kind, index) => ({
      kind,
      at: new Date(base + (index + 10) * 60_000).toISOString(),
      role: kind === "activate_first" ? "company_admin" : "secretary",
      result: "passed",
      persistedEffect: `${kind} retained in the local instance`
    })),
    pilotState: {
      observedAt: "2026-09-21T17:59:00.000Z",
      membersByState: [{ state: "active", count: "5" }],
      tableRowCounts: { members: "5", votes: "1", vote_certificates: "1", minutes: "1" }
    }
  };
}

describe("SR-102 human-acceptance receipt shape", () => {
  it("accepts a complete synthetic receipt bound to the candidate", () => {
    const receipt = verifyHumanAcceptanceReceipt(syntheticReceipt(), CANDIDATE);
    expect(receipt.actions).toHaveLength(REQUIRED_HUMAN_ACTIONS.length);
    expect(HumanAcceptanceReceiptSchema.safeParse(syntheticReceipt()).success).toBe(true);
  });

  it("refuses a receipt for another candidate", () => {
    expect(() =>
      verifyHumanAcceptanceReceipt(syntheticReceipt(), {
        ...CANDIDATE,
        sourceTreeSha256: "b".repeat(64)
      })
    ).toThrow(/does not bind the candidate/u);
  });

  it("refuses a receipt that skips a required human action", () => {
    const receipt = syntheticReceipt();
    const actions = receipt.actions.filter((action) => action.kind !== "activation_restart");
    expect(() =>
      verifyHumanAcceptanceReceipt({ ...receipt, actions: [...actions, actions[0]] }, CANDIDATE)
    ).toThrow(/activation_restart/u);
  });

  it("refuses secret-shaped material anywhere in the receipt", () => {
    const withCode = syntheticReceipt();
    withCode.person.statement += " The code was ABC-DEFG and it worked.";
    expect(() => verifyHumanAcceptanceReceipt(withCode, CANDIDATE)).toThrow(/secret-shaped/u);
    const withToken = syntheticReceipt();
    withToken.actions[0]!.persistedEffect = `restart ${"A".repeat(43)} consumed`;
    expect(() => verifyHumanAcceptanceReceipt(withToken, CANDIDATE)).toThrow(/secret-shaped/u);
  });

  it("refuses unordered actions, a voting secretary and a missing member inventory", () => {
    const unordered = syntheticReceipt();
    unordered.actions[1]!.at = "2026-09-19T00:00:00.000Z";
    expect(() => verifyHumanAcceptanceReceipt(unordered, CANDIDATE)).toThrow(/in order/u);
    const votingSecretary = syntheticReceipt();
    votingSecretary.members[1]!.votingWeight = 1;
    expect(() => verifyHumanAcceptanceReceipt(votingSecretary, CANDIDATE)).toThrow(
      /non-voting secretary/u
    );
    const thin = syntheticReceipt();
    thin.pilotState.membersByState = [{ state: "active", count: "2" }];
    expect(() => verifyHumanAcceptanceReceipt(thin, CANDIDATE)).toThrow(/inventory/u);
  });

  it("verifies the checked-in receipt when one exists, and states its absence otherwise", async () => {
    const file = path.resolve(import.meta.dirname, "../..", HUMAN_ACCEPTANCE_RECEIPT_PATH);
    const text = await readFile(file, "utf8").catch((error: NodeJS.ErrnoException) => {
      if (error.code !== "ENOENT") throw error;
      return null;
    });
    if (text === null) {
      // Not a skip: the absence is the asserted fact while SR-102 stays UNRESOLVED.
      expect(text).toBeNull();
      return;
    }
    const parsed = HumanAcceptanceReceiptSchema.parse(JSON.parse(text));
    expect(parsed.client.name).toBe("Claude Code");
  });
});
