# ADR 0002: TypeScript 7 and third-party declaration isolation

- Status: accepted implementation constraint
- Date: 2026-08-29
- Authority: D2-052 and frozen toolchain pins

## Context

The frozen toolchain pins TypeScript 7.0.2 and Drizzle ORM 0.45.2. Drizzle's published
declaration bundle includes optional Gel/MySQL/SingleStore declarations and TypeScript
5-era interface shapes that fail TypeScript 7 declaration checking even when BoardAgent
imports only `drizzle-orm/pg-core`. Those errors are in dependency declarations, not in
BoardAgent source.

## Decision

`skipLibCheck` is enabled at the workspace boundary. All BoardAgent source remains under
strict TypeScript checks with `exactOptionalPropertyTypes`, `noUncheckedIndexedAccess`,
`noImplicitOverride`, `noImplicitReturns` and composite project references. Runtime
boundary behavior is proved through strict Zod schemas and integration tests. Package
pins and lockfile integrity prevent an unchecked declaration update from arriving
silently.

## Consequences

The compiler does not validate the internals of third-party `.d.ts` files. This is not a
waiver for BoardAgent source and does not relax runtime schemas. The compatibility lane
must be rerun before any Drizzle or TypeScript upgrade; removing `skipLibCheck` is the
preferred future state once the pinned declarations are compatible.
