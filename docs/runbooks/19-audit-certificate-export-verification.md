# 19 — Audit, certificate, and export verification

**Owners:** secretariat/auditor for scoped exports; deployment/security owner for trusted
keys. **Purpose:** verify evidence without trusting keys embedded only in the artifact.

## Trusted key set

Obtain active and historical evidence public JWKs through an authenticated, independently
verified route. Record the set's canonical SHA-256 and custody source. An exported bundle's
own key is evidence to compare, not a trust anchor.

## Vote certificate

1. Fetch `get_vote_certificate` through an entitled session and export its bounded bundle.
2. Offline, with no BoardAgent secrets or network dependency, run:

   ```sh
   node scripts/dist/operator.js verify-certificate BUNDLE.json TRUSTED_KEYS.json
   ```

3. Require exit zero and `valid: true`. Repeat with a deliberately wrong trust set in the
   controlled verification suite; it must fail. The public `/verify/certificate` route may
   verify an opaque public ID or bundle but returns only a generic result.

## Audit chain

1. Use `export_audit_chain` with exact board/sequence scope and confirmation.
2. Poll `get_export_status`, then obtain all `read_export_chunk` bytes in order. Preserve
   the frozen export scope and encrypted package hash.
3. On the offline verifier host, use the matching data KEK file and independent trust set:

   ```sh
   node scripts/dist/operator.js verify-chain \
     ENCRYPTED_EXPORT DATA_KEK_FILE TRUSTED_KEYS.json
   ```

4. Require exact range, event hashes/links, snapshot head, checkpoints, and signatures. A
   failure must report the first break/reason; never discard or regenerate the artifact to
   hide it. Reject non-fatal UTF-8 decoding, noncanonical JSON bytes, malformed PostgreSQL
   text encodings, duplicate exact trusted-checkpoint rows, or a key found only inside the
   artifact.

Record artifact/scope/trust-set hashes, signing key IDs, verifier build/source digest,
offline environment, exit/result, first break if any, and custodian. Use
`delete_export_artifact` only after retention/custody confirmation; it deletes the temporary
encrypted artifact, not governance/audit records.

## Signed audit export packages

New audit exports use `boardagent.export-package.v2` inside the existing encrypted
container. An Ed25519 attestation binds the exact event/checkpoint bytes, approved scope,
request, snapshot, instance and current checkpoint to the independently trusted evidence
key. Before issuing it, the worker verifies the retained audit chain, including payloads
hidden by this export, in the same repeatable-read snapshot. The verifier reports
`proof: signed_export_snapshot`, recomputes every visible event and verifies included
checkpoints. Redacted rows disclose no extra payload. `anchorSequence: null` means the
latest checkpoint does not intersect this exported range; `attestedRangeLastSequence`
identifies the end covered by the export attestation instead.
The attestation is not a cadence checkpoint and cannot cure an overdue audit history.

Older verifiers reject the new package version. Retain the matching verifier build with
the exported artifact. The `verify-chain` command rejects every unsigned legacy v1 audit
package with `legacy_export_attestation_required`; it never silently falls back to a
weaker proof after an attestation is removed. New audit publication also requires the
attestation. The lower-level legacy library can still inspect complete, checkpoint-end-
anchored event bytes for forensic use, but that does not authenticate package scope,
request, snapshot or instance claims. Unsigned redactions and unsigned suffixes refuse. Preserve the original artifact and failure; request
a newly confirmed export using the repaired build if a fresh proof is needed. Never edit
old bytes or treat a newly issued attestation as evidence of an earlier signing time.
