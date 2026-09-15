# Expired untouched first invitation — 10 September 2026

BA-E2E-0043: the synthetic pilot's first invitation expired before any passkey registration.
The existing one-use bootstrap correctly refuses another initialization, and initial
activation requires a completed registration ceremony. There was no supported way to
replace the expired, untouched first invitation while preserving the instance.

Under the project owner's delegated instruction to finish securely with understandable recovery,
add `bootstrap renew-first-invitation REQUEST.json` to the existing local operator family.
This is an explicit narrow implementation addition; it is not attributed to a frozen
matrix rule that specified renewal. No frozen plan, role grant or verification threshold
changes. No additional MCP tool, HTTP endpoint, schema migration or audit vocabulary.

The managed serializable migrator/bootstrap transaction takes the existing singleton lock,
then the prior invitation and member locks in enrollment order. Require exact expected
instance, organization, canonical HTTPS resource, member and prior invitation; the sole
human remains invited at its initial row version, has the original active admin and
secretariat roles/secretary seat, and has no credential or activation challenge history.
Require expired, unconsumed, unrevoked latest invitation with matching initial bootstrap
issuance evidence. Revoke it, append a fresh 32-byte secret hash invitation with 24-hour
expiry, and append both existing enrollment audit events atomically. Never replay the
new token on a retry; never create a person, role, attestation or active account.

An abandoned enrollment page or unconsumed public WebAuthn challenge is insufficient to
block renewal forever. The predecessor's expiry and revocation prevent its completion;
completed registration closes this narrow renewal route. Personal passkey registration,
operator proofing and first activation remain mandatory. Lost successful output requires
read-only inspection and, if unrecoverable, waiting for the successor to expire. This is
not a reset or a way to replace a live invitation or established identity.

Implementation: `lib/db/src/transactions/bootstrap.ts`, `scripts/src/bootstrap.ts`,
`scripts/src/operator.ts`. Existing bootstrap/migrator grants suffice; runtime server and
worker roles receive no new privilege. Manual: `docs/runbooks/31-expired-first-invitation.md`.
Tests: `tests/integration/bootstrap-renewal.postgres.test.ts`,
`tests/operations/bootstrap-renewal-cli.spec.ts`,
`tests/protocol/bootstrap-renewal-http.postgres.test.ts`, and the management-secretary
case of `tests/protocol/secretary-handoff.postgres.test.ts`. These use synthetic identities
and real signed test authenticator responses; they are not actual human SR102 acceptance.
