# ADR 0001: MCP and OAuth compatibility bundle

- Status: accepted at Gate 2
- Date: 2026-08-28
- Authority: D2-003 through D2-008, D2-036 through D2-038

## Decision

BoardAgent exposes one canonical resource and sessionless `POST /mcp` endpoint. The
primary protocol is MCP `2026-07-28` with `server/discover`, per-request metadata and
multi-round-trip `input_required` forms. The bounded compatibility profile is
`2025-11-25` and is read/resource/prompt only. It never lists or stages an H tool. The
SDK legacy input-required shim is disabled.

The authorization bundle is the exact bundle incorporated by the MCP 2026-07-28
authorization specification: OAuth 2.1 draft 13, RFC 6750, RFC 7591 fallback, RFC 8414,
RFC 8707, RFC 9207, RFC 9728 and Client ID Metadata Documents draft 00, plus OIDC
Discovery/Registration for the optional federation adapter. A newer IETF draft does not
silently replace this protocol contract; upgrade requires an ADR and compatibility net.

The frozen client matrix is exact, not brand-equivalent:

- modular `@modelcontextprotocol/{client,core,node,server}` `2.0.0` is the
  conformance harness;
- `mcporter` `0.13.7` (integrity
  `sha512-+xfZwrFv+oO0YOyHUQzyBRaOGomJhMWPtoINGfY6rtEk7s4jW6T+osnjPr/1XAmIpN8J0/P03XiLnTIUkltPzg==`)
  is the independent modern acceptance client; and
- released OpenClaw tag `v2026.7.1-2`, package `2026.7.1` (integrity
  `sha512-ge/Xss99CHAjPL/ikmH/UFoiOrjcxDB4sW3y9mhyCD+dYW3wzV7TKbAVdkrXFgAG2d2BjpJofP97zUZ+umxo8g==`),
  with embedded SDK `1.29.0`, is the legacy read/resource/prompt client.

`tests/protocol/released-client-matrix.spec.ts` executes both published client
runtimes through a locally trusted HTTPS endpoint and the protected bearer-token
boundary. It proves the exact tool count for each profile plus an entitled read,
resource read and prompt fetch. OAuth authorization-server issuance and browser
ceremonies are separately exercised by the T6 auth/browser suites.

## Consequences

Every action-capable client must implement form elicitation MRTR. Legacy clients remain
useful for entitled reads but cannot govern. Tokens bind exactly to the normalized
`https://host/mcp` audience/resource. The path-aware protected-resource metadata route is
`/.well-known/oauth-protected-resource/mcp`.

The two released clients are test-only dependencies and do not enter the production
image. Their package lifecycle scripts are explicitly denied; the acceptance proof uses
their published JavaScript runtime. Changing either version, integrity, protocol lane or
test boundary requires recertification under this ADR.

## Rejected alternatives

Two resource URIs would double audience and metadata testing. Default SDK legacy action
shims would hide a client capability gap. Calling the bundle “latest OAuth” would make a
future draft change production semantics without review.
