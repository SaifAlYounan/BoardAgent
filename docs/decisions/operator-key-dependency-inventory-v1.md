# Operator key dependency inventory — database prerequisite

Recorded 9 September 2026 under the actual operational completion instruction.
This additive implementation preserves frozen files and existing runtime permissions.
It supplies read-only database facts for F7; it does not authorize or perform replacement.

`inspectKeyDependenciesInTransaction` calls the protected
`boardagent_inspect_key_dependencies` function from SQL0127. Only the migrator/operator
may execute it, in a serializable read-only bootstrap transaction. The caller supplies
exact instance, organization and key UUIDs. Wrong targets or transaction modes refuse.
Server, worker and backup roles cannot gain execution by claiming bootstrap scope.

The function discovers every declared foreign-key column referencing the key registry ID.
The current schema has 11, including audit_recoveries.signing_key_id, which was absent from
the original 10-entry inventory. Explicit operator read policies on those 11 tables prevent
FORCE RLS from hiding relevant rows. A newly discovered table lacking the explicit inventory
policy refuses the inspection instead of being reported empty. A new foreign-key column
on an already authorized table is discovered automatically. Runtime row/column grants are
unchanged; these additional reads belong only to the technical operator.

For each dependency the result includes table/column, matching row count and a digest.
All states count, including revoked or otherwise terminal rows. Actual row contents remain
inside PostgreSQL: each complete typed row becomes PostgreSQL 18 JSONB text in fixed
UTC/ISO/hex formatting, then SHA-256. The sorted row hashes feed a SHA-256 chain beginning
with 32 zero bytes. The explicitly versioned digest method is
postgresql 18-jsonb-row-sha256-chain-v1; it is change-detection metadata, not a replacement
for canonical governance evidence or an independent signature. Output has no ciphertext,
contact values, secret bytes or full public-key row. Key-state and audit-head hashes bind
other relevant database state. A canonical state digest excludes only the observation time.

Inventory bounds are 256 referencing columns and 1 million reference occurrences across all
columns. A row with two references counts twice. The function checks the count before
hashing matching rows, streams row hashes in order and refuses unsupported capacity.
This bounds output and working state; it does not prove native performance at those maxima.
A future schema addition needs its explicit operator read policy and corresponding review.

Tests cover all five purposes, real recovery dependencies, ciphertext/state changes,
terminal-row retention, repeated/concurrent snapshots, newly declared columns, an unknown
FORCE-RLS table, wrong targets/transaction modes and actual runtime-role refusals. Display
settings initially changed the key-state digest; fixed function settings close that failure.
The complete migration catalog also caught a missing explicit pg_temp-last search path;
SQL0127 now meets the existing rule. No threshold was changed.

Three older runtime-compatibility tests tried to fabricate a post-bootstrap migration row,
which SQL0126 now correctly refuses. They now install a synthetic future migration through
the actual migrator and its audit receipt, then prove the older server/worker refuse startup
or withdraw readiness. Direct runtime ledger-write denial remains tested. No migration
guard, receipt requirement or production source was weakened for fixture setup.

Still required: references inside typed JSON/envelopes, in-flight signing work and explicit
logical/physical/WAL/off-host file inventories; strict operator preparation; dependency
completeness at apply; immutable lifecycle/audit receipts and exact retries; all five key
transitions; revocations, webhook rewrap, runtime invalidation and pre/post-transition
restore proof. This database function alone cannot establish filesystem key custody or
that replacing a key is safe. It is not yet exposed as an operator command.
