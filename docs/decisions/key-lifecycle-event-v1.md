# Exact key-change evidence — 9 September 2026

This implements the strict payload for the reserved `key_lifecycle_changed` event under
the [operational completion instruction](operational-completion-instruction-2026-09-08.md)
and [recorded registry addition](operational-maintenance-amendment-v1.json).
It does not implement the database transition or an operator command.

`lib/audit/src/key-lifecycle-event.ts` defines one exact versioned payload. It identifies
the operation, request hash, installation, organization, purpose, prior key, resulting
prior-key state and optional replacement. It also records the dependency/material
inventory hashes, operator reference, reason and six bounded effect counts. No private
JWK, key bytes, decrypted credential, token or additional unrecognized field is accepted.
A hash in this payload does not itself prove actual filesystem custody or a human act.

The outer audit event must name the same operation and time, use the CLI origin, and have
no human member/client/token/board principal. The future database operation must derive and
independently enforce these facts from its real authority and committed changes.

- Purpose and algorithm must match. Public-material hashes are present for OAuth/evidence
  signers and null for symmetric keys. The older data registry has a derived key identifier;
  this schema does not invent an independently recorded full legacy-key fingerprint.
  Public-material hashes use only canonical cryptographic JWK fields: `crv`, `kty`, `x`
  and, for EC keys, `y`. Renaming `kid` or changing descriptive fields cannot create a
  new key. The [preparation contract](key-lifecycle-preparation-v1.md) specifies this check.
- Replacement creates a distinct key ID/kid and public identity, activates it at the event's
  recording time and preserves the old identity and warning times. Replacing an already
  retired or compromised key is representable so service can recover after an incident.
  The future database operation must refuse a stale target when another key is active.
- Ordinary retirement cannot rewrite an earlier retirement. Compromise records a declared
  earliest suspected time separately from recording time. A subsequent new warning can
  move the suspicion earlier; it cannot heal history by moving it later. Exact operation
  retries must return the original receipt, not construct a new before/after transition.
- All times use six fractional digits and real UTC calendar validation. Comparisons retain
  microseconds. `recordedAt` equals the audit transaction timestamp used by the existing
  append function, not a claimed external timestamp or the instant a person discovered an
  incident. No caller-supplied timestamp may replace that database value in application.

The parser's successful result is only a structurally consistent evidence object. It
cannot prove the effects happened, a file is installed or a service restarted. SQL must
atomically bind the real transition, immutable operation and audit event. A failed audit
append must roll back the authority change, and a lost response must be inspectable by
the operation ID without repeating effects.

Tests in `tests/unit/key-lifecycle-event.test.ts` exercise all 15 purpose/operation pairs,
retirement/compromise preservation, microsecond bounds, changed identity/material/time,
extra private fields, non-operator envelopes and post-hash alteration. The initial bare
claim was accepted and is now refused.22tests/sixfiles passed with typecheck/lint, including
the 100,000 seeded canonical-event property, recovery operator and backup/restore regressions.
An earlier lint failure from a control-character regex was repaired with explicit scalar
checks, without suppressing the rule.

The expanded PostgreSQL audit-chain suite separately exposed the still-unfinished database
catalog:136SQL events versus137registered events. That failure remains open. The database
currently refuses the new event. Add its SQL catalog entry alongside the protected actual
operation and receipt checks; do not merely permit arbitrary new audit claims. The three
earlier documentation closure failures remain open too. This is not full qualification,
implemented lifecycle, deployment or human acceptance evidence.
