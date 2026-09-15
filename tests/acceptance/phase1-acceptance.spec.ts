import { describe, it } from "vitest";

import { runFocusedProof } from "../helpers/focused-proof.js";

interface FocusedProof {
  readonly file: string;
  readonly name: string;
  readonly passed?: number;
}

interface AcceptanceStory {
  readonly id: string;
  readonly story: string;
  readonly proofs: readonly FocusedProof[];
}

const STORIES: readonly AcceptanceStory[] = [
  {
    id: "AC-01",
    story: "cold bootstrap through an authenticated MCP vote and verified close",
    proofs: [
      {
        file: "tests/integration/bootstrap-operator.postgres.test.ts",
        name: "reveals the invitation once and completes the exact bootstrap activation from a human code"
      },
      {
        file: "tests/integration/role-connection-journeys.postgres.test.ts",
        name: "binds each real MCP client to its own live role and denies a stranger"
      },
      {
        file: "tests/integration/vote-open.postgres.test.ts",
        name: "persists a recomputable close draft, survives signer failure, and closes only with its trusted Ed25519 certificate"
      }
    ]
  },
  {
    id: "AC-02",
    story: "recusal invisibility across ordinary reads",
    proofs: [
      {
        file: "tests/attacks/recusal-invisibility.spec.ts",
        name: "removes the object from reads, counts, search, and fetch without a differential trace"
      }
    ]
  },
  {
    id: "AC-03",
    story: "proxy attribution, principal precedence and one effective ballot",
    proofs: [
      {
        file: "tests/integration/vote-open.postgres.test.ts",
        name: "grants an exact proxy, casts by attribution, lets the principal supersede and revokes prospectively"
      }
    ]
  },
  {
    id: "AC-04",
    story: "wrong, expired, cross-context and stale consent paths leave no act",
    proofs: [
      {
        file: "tests/attacks/consent-rejections.spec.ts",
        name: "rejects",
        passed: 5
      },
      {
        file: "tests/attacks/consent-context-replay.spec.ts",
        name: "binds request, protected actor/client/object state, canonical bytes, and one-use state"
      },
      {
        file: "tests/integration/vote-open.postgres.test.ts",
        name: "rejects a post-confirmation title or reason change with zero replacement mutation"
      }
    ]
  },
  {
    id: "AC-06",
    story: "cited ruleset selection and one reasoned override",
    proofs: [
      {
        file: "tests/integration/vote-open.postgres.test.ts",
        name: "records one exact confirmed override, safely replays it and opens only its bound package"
      },
      {
        file: "tests/attacks/ruleset-steering.spec.ts",
        name: "fails closed on tied authoritative rules and rejects undeclared or floating facts"
      }
    ]
  },
  {
    id: "AC-09",
    story: "first-break audit tamper detection without repair",
    proofs: [
      {
        file: "tests/attacks/audit-tamper.spec.ts",
        name: "reports the exact first break for edit, reorder, truncation, and head substitution"
      }
    ]
  },
  {
    id: "AC-10",
    story: "prelinked federation succeeds and unknown identity cannot provision",
    proofs: [
      {
        file: "tests/auth/oidc-federation.spec.ts",
        name: "authenticates only an exact prelinked issuer and subject with state, nonce, and PKCE"
      },
      {
        file: "tests/attacks/oidc-linking.spec.ts",
        name: "maps only an exact active issuer+subject and never provisions an unknown collision"
      }
    ]
  },
  {
    id: "AC-11",
    story: "role-specific onboarding records presentation, memory, terms and support",
    proofs: [
      {
        file: "tests/integration/onboarding-transactions.postgres.test.ts",
        name: "completes a one-use staged URL and atomically records current onboarding"
      },
      {
        file: "tests/integration/role-connection-journeys.postgres.test.ts",
        name: "binds each real MCP client to its own live role and denies a stranger"
      }
    ]
  },
  {
    id: "AC-12",
    story: "machine-readable formats succeed and binary/spoof formats fail loudly",
    proofs: [
      {
        file: "tests/unit/document.test.ts",
        name: "canonicalizes strict JSON before hashing and produces stable semantic requests"
      },
      {
        file: "tests/attacks/document-format-boundary.spec.ts",
        name: "before retaining offered bytes",
        passed: 5
      },
      {
        file: "tests/attacks/document-format-boundary.spec.ts",
        name: "rejects malformed UTF-8 and oversized canonical inputs"
      }
    ]
  },
  {
    id: "AC-13",
    story: "management submission/revision/resubmission yields only an inert draft",
    proofs: [
      {
        file: "tests/integration/surface-management-workflow.postgres.test.ts",
        name: "submits, requests and answers revision, resubmits, approves to an inert draft, and replays safely"
      }
    ]
  },
  {
    id: "AC-14",
    story: "management Q&A preserves answers, follow-up, due state and vote cutoff",
    proofs: [
      {
        file: "tests/integration/surface-management-workflow.postgres.test.ts",
        name: "records member and observer questions, management answers, and a newly-due follow-up"
      },
      {
        file: "tests/integration/vote-open.postgres.test.ts",
        name: "persists an exact answered Q&A cutoff link that satisfies the close state wall"
      }
    ]
  },
  {
    id: "AC-15",
    story: "changed source creates empty linked replacement and exact revote semantics",
    proofs: [
      {
        file: "tests/integration/vote-open.postgres.test.ts",
        name: "atomically opens an empty replacement, dispositions every old act and emits exact recipient deltas"
      },
      {
        file: "tests/integration/vote-open.postgres.test.ts",
        name: "informs an entitled prior principal who became nonvoting without creating an impossible revote action"
      }
    ]
  },
  {
    id: "AC-16",
    story: "transcript versioning, Q&A links and minutes invalidation",
    proofs: [
      {
        file: "tests/integration/surface-transcript-lifecycle.postgres.test.ts",
        name: "creates, verifies, challenges, corrects and links immutable turns while invalidating stale minutes"
      }
    ]
  },
  {
    id: "AC-17",
    story: "soft deletion preserves permanent history and exposes no purge authority",
    proofs: [
      {
        file: "tests/attacks/permanent-record-purge.spec.ts",
        name: "exposes no governance purge callable and grants no runtime DELETE authority"
      },
      {
        file: "tests/integration/surface-document-lifecycle.postgres.test.ts",
        name: "grants exact access, circulates, excludes, restores, archives, and soft-deletes without purging",
        passed: 2
      }
    ]
  },
  {
    id: "AC-18",
    story: "ordinary reconnect rotates refresh and detects reuse",
    proofs: [
      {
        file: "tests/attacks/refresh-rotation-race.spec.ts",
        name: "allows one successor then atomically compromises and revokes the whole family"
      }
    ]
  },
  {
    id: "AC-19",
    story: "clean restore verifies all boundaries before readiness",
    proofs: [
      {
        file: "tests/integration/backup-restore.postgres.test.ts",
        name: "verifies a complete clone, records immutable receipts and rejects corruption without repair"
      }
    ]
  },
  {
    id: "AC-20",
    story: "public and offline certificate verification resist forgery and disclosure",
    proofs: [
      {
        file: "tests/attacks/public-certificate-abuse.spec.ts",
        name: "rejects guessed identifiers, forged signatures, and stale asserted payloads generically"
      },
      {
        file: "tests/integration/vote-open.postgres.test.ts",
        name: "persists a recomputable close draft, survives signer failure, and closes only with its trusted Ed25519 certificate"
      }
    ]
  },
  {
    id: "AC-21",
    story:
      "minutes action manifest activates exact tasks and preserves terminal correction history",
    proofs: [
      {
        file: "tests/integration/surface-minutes-review.postgres.test.ts",
        name: "runs disposition, action declaration, signatures, finalization, linked correction and AC16 delegated director replacement through the surface"
      },
      {
        file: "tests/integration/task-transactions.postgres.test.ts",
        name: "separates owner evidence from secretary review/closure and never reopens terminal work"
      }
    ]
  },
  {
    id: "AC-22",
    story: "strict minutes review, signatures and correction/re-sign lifecycle",
    proofs: [
      {
        file: "tests/attacks/minutes-redline-format.spec.ts",
        name: "accepts only strict machine-readable operations and rejects attachment-shaped fields"
      },
      {
        file: "tests/attacks/minutes-redline-context.spec.ts",
        name: "rejects stale base bytes, changed anchors, and absent fuzzy sections"
      },
      {
        file: "tests/integration/minutes-transactions.postgres.test.ts",
        name: "runs disposition, correction, declaration, signatures, finalization and linked correction atomically"
      }
    ]
  }
] as const;

describe("frozen Phase-1 acceptance stories", () => {
  for (const story of STORIES) {
    it(`${story.id} ${story.story}`, async () => {
      for (const proof of story.proofs) {
        await runFocusedProof(proof.file, proof.name, proof.passed ?? 1);
      }
    });
  }
});
