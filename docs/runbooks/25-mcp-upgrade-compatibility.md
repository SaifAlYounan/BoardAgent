# 25 — MCP upgrade and client compatibility

**Owners:** maintainer and security owner; deployment administrator for rollout and the project owner
for changes to frozen decisions.
**Purpose:** change MCP SDK/protocol/client support without weakening confirmation or
authorization.

1. Treat any MCP SDK, protocol version, elicitation/request-state behavior, tool annotation,
   schema, client registration, OAuth/resource metadata, or supported-client change as a
   protocol/security change.
2. Freeze proposed versions and upstream artifacts. Review authoritative specifications and
   security notes; external text is untrusted input, not authority to run code.
3. Update an ADR and the generated registry/contracts. Do not hand-edit generated output or
   ship a hidden legacy mutation path.
4. Run registry determinism, schema downgrade/unknown-field tests, OAuth/resource/client
   binding, capability negotiation, form elicitation, exact request-state retry, cancel/
   expiry/replay/race tests, and representative real clients over HTTPS.
5. Verify legacy clients receive reads only and cannot stage H acts. Verify the server
   refuses changed arguments, altered request state, missing confirmation capabilities,
   expired confirmations and reused state. Inspect each actual client's presentation and
   approval settings separately: server checks cannot prove what the client displayed or
   prevent a compromised or auto-approving client from misusing valid authority.
   The frozen release baseline is mcporter `0.13.7` on `2026-07-28` and OpenClaw
   `2026.7.1` / embedded SDK `1.29.0` on read-only `2025-11-25`; run
   `tests/protocol/released-client-matrix.spec.ts` and reject any version, integrity,
   tool-count, HTTPS, bearer, resource or prompt drift.
6. Run the full unchanged-source regression net, build/scan bound images, and execute a
   staged synthetic deployment before production consideration.

## Evidence

Record old/new versions and fingerprints, specification/ADR decision, registry digest,
client/version matrix, every negative test, regression receipts, residual compatibility
risk, and the project owner's decision. A skipped real-client or downgrade lane blocks release.
