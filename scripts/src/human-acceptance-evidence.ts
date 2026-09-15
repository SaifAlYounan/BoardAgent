import { z } from "zod";

import { UuidV7Schema } from "@boardagent/contracts";

/**
 * SR-102 human-acceptance receipt (`boardagent.human-acceptance-receipt.v1`).
 *
 * The receipt is written by hand after the project owner, with their own passkey and their own
 * Claude Code, activates the first account, enrolls the Mining Exploration Co. board,
 * exercises the activation restart and the replacement recovery once each, and runs one
 * full cycle. It binds the exact candidate, names the client, inventories the retained
 * pilot state and carries the project owner's statement. It never carries a secret: activation codes,
 * invitation and restart tokens, cookies and bearer tokens are refused by shape.
 * Synthetic authenticators cannot produce this receipt; the SR-102 row flips only when
 * the checked-in file verifies against the candidate under test.
 */
export const HUMAN_ACCEPTANCE_RECEIPT_PATH = "docs/evidence/human-acceptance-receipt.json";

const Sha256 = z.string().regex(/^[0-9a-f]{64}$/u);
const GitCommit = z.string().regex(/^[0-9a-f]{40}$/u);
const Text = z.string().trim().min(1).max(2048);
const HttpsOrigin = z
  .string()
  .url()
  .refine((value) => {
    const url = new URL(value);
    return url.protocol === "https:" && url.pathname === "/" && !url.search && !url.hash;
  }, "public base URL must be a bare https origin");

/** Every step the beta definition of done demands from a real person, in order. */
export const REQUIRED_HUMAN_ACTIONS = [
  "activate_first",
  "client_login",
  "onboarding",
  "invite_members",
  "member_enrollment",
  "activation_restart",
  "replacement_recovery",
  "document_import",
  "circulate_document",
  "create_meeting",
  "create_vote",
  "stage_ballots",
  "close_vote",
  "verify_certificate",
  "finalize_minutes",
  "sign_minutes",
  "tasks_opened",
  "reconnect_next_day"
] as const;

export const HumanActionKind = z.enum(REQUIRED_HUMAN_ACTIONS);

const MemberRole = z.enum(["company_admin", "secretary", "chair", "director"]);

export const HumanAcceptanceReceiptSchema = z
  .object({
    schemaVersion: z.literal("boardagent.human-acceptance-receipt.v1"),
    recordedAt: z.iso.datetime({ offset: false }),
    candidate: z.object({ gitCommit: GitCommit, sourceTreeSha256: Sha256 }).strict(),
    instance: z
      .object({
        publicBaseUrl: HttpsOrigin,
        schemaVersion: z.number().int().min(170),
        releaseImageDigest: Sha256.optional()
      })
      .strict(),
    client: z
      .object({
        name: z.literal("Claude Code"),
        version: z.string().regex(/^\d+\.\d+\.\d+$/u)
      })
      .strict(),
    person: z
      .object({
        displayName: Text,
        statement: z.string().trim().min(40).max(8192),
        passkeyAuthenticator: Text
      })
      .strict(),
    members: z
      .array(
        z
          .object({
            memberId: UuidV7Schema,
            displayName: Text,
            role: MemberRole,
            votingWeight: z.number().int().min(0).max(1),
            activatedAt: z.iso.datetime({ offset: false })
          })
          .strict()
      )
      .min(4)
      .max(16),
    actions: z
      .array(
        z
          .object({
            kind: HumanActionKind,
            at: z.iso.datetime({ offset: false }),
            role: MemberRole,
            objectId: UuidV7Schema.optional(),
            result: z.literal("passed"),
            persistedEffect: Text
          })
          .strict()
      )
      .min(REQUIRED_HUMAN_ACTIONS.length)
      .max(256),
    pilotState: z
      .object({
        observedAt: z.iso.datetime({ offset: false }),
        membersByState: z.array(
          z.object({ state: Text, count: z.string().regex(/^(0|[1-9][0-9]*)$/u) }).strict()
        ),
        tableRowCounts: z.record(
          z.string().regex(/^[a-z][a-z0-9_]{0,62}$/u),
          z.string().regex(/^(0|[1-9][0-9]*)$/u)
        )
      })
      .strict()
  })
  .strict();

export type HumanAcceptanceReceipt = z.infer<typeof HumanAcceptanceReceiptSchema>;

export interface AcceptanceCandidate {
  readonly gitCommit: string;
  readonly sourceTreeSha256: string;
}

// Shapes that must never appear in evidence: the 43-character one-use handoff and
// invitation tokens, the XXX-XXXX activation code, and any bearer/cookie material.
const SECRET_SHAPES: readonly RegExp[] = [
  /(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/u,
  /\b[A-HJ-NP-Z2-9]{3}-[A-HJ-NP-Z2-9]{4}\b/u,
  /#[A-Za-z0-9_-]{20,}/u,
  /\b(?:bearer|cookie|set-cookie|authorization)\b\s*[:=]/iu,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/u
];

function collectStrings(value: unknown, into: string[]): void {
  if (typeof value === "string") into.push(value);
  else if (Array.isArray(value)) for (const item of value) collectStrings(item, into);
  else if (value !== null && typeof value === "object")
    for (const item of Object.values(value as Record<string, unknown>)) collectStrings(item, into);
}

/**
 * Verifies a receipt against the candidate under test. Throws with a plain reason; the
 * caller decides whether SR-102 is PROVEN. Never mutates or reads outside its input.
 */
export function verifyHumanAcceptanceReceipt(
  value: unknown,
  candidate: AcceptanceCandidate
): HumanAcceptanceReceipt {
  const receipt = HumanAcceptanceReceiptSchema.parse(value);
  if (
    receipt.candidate.gitCommit !== candidate.gitCommit ||
    receipt.candidate.sourceTreeSha256 !== candidate.sourceTreeSha256
  ) {
    throw new Error("SR-102 receipt does not bind the candidate under test");
  }
  const strings: string[] = [];
  collectStrings(value, strings);
  for (const text of strings) {
    if (SECRET_SHAPES.some((shape) => shape.test(text))) {
      throw new Error("SR-102 receipt carries secret-shaped material");
    }
  }
  const kinds = new Set(receipt.actions.map((action) => action.kind));
  const missing = REQUIRED_HUMAN_ACTIONS.filter((kind) => !kinds.has(kind));
  if (missing.length > 0) {
    throw new Error(`SR-102 receipt lacks required human actions: ${missing.join(", ")}`);
  }
  const recordedAt = Date.parse(receipt.recordedAt);
  let previous = Number.NEGATIVE_INFINITY;
  for (const action of receipt.actions) {
    const at = Date.parse(action.at);
    if (at < previous || at > recordedAt) {
      throw new Error("SR-102 receipt actions must be in order and precede the record");
    }
    previous = at;
  }
  const secretaries = receipt.members.filter((member) => member.role === "secretary");
  const voters = receipt.members.filter((member) => member.votingWeight === 1);
  if (secretaries.length !== 1 || secretaries[0]?.votingWeight !== 0 || voters.length < 3) {
    throw new Error("SR-102 receipt needs one non-voting secretary and at least three voters");
  }
  const memberIds = new Set(receipt.members.map((member) => member.memberId));
  if (memberIds.size !== receipt.members.length) {
    throw new Error("SR-102 receipt repeats a member");
  }
  const activeMembers = receipt.pilotState.membersByState.find((row) => row.state === "active");
  if (activeMembers === undefined || Number(activeMembers.count) < receipt.members.length) {
    throw new Error("SR-102 receipt inventory does not retain every listed member as active");
  }
  return receipt;
}
