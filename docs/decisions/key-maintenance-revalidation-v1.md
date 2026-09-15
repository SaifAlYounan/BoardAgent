# Rechecking a prepared key change — 9 September 2026

A prepared change must not silently apply to different database facts. Migration 0130
adds `boardagent_lock_key_maintenance_snapshot`, which compares the full prepared inventory
against a fresh serializable snapshot. Only the new observation time is excluded. Missing,
additional and changed facts are refused, including changed key state, audit history and
queued work. The caller cannot substitute an assertion that two hashes matched.

The function requires a writing serializable bootstrap transaction and operator database
authority. It takes the audit-head row lock first, the existing purpose advisory lock second,
then the key row lock. Its locks last until the caller commits or rolls back. It checks the
exact six-digit UTC preparation and expiry values and their thirty-minute interval. Expiry
is checked against the database clock after acquiring locks, including time spent waiting.
Prepared JSON is bounded to 256 KiB, above the bounded inventory's supported metadata size;
larger input is refused before locks and inventory work.

The new function does not change keys, create an operation receipt or authorize a later
transaction. The future application must call it inside the same transaction as the real
change and audit event. A serialization conflict requires a new transaction and revalidation.
An expired or stale request requires new preparation. Exact retries of an already completed
operation must inspect its immutable receipt before evaluating changed current state.

This is not a stop-the-world barrier. It does not prove processes stopped, prevent every
unrelated dependency write or verify private-file custody. The eventual maintenance operation
still needs service fencing, checks for work in progress and purpose-specific effects. Old
initial-registration functions retain their existing lock order; their interaction with the
complete lifecycle must be resolved before qualification. No previous migration was edited.

`tests/integration/key-maintenance-revalidation.postgres.test.ts` executes seven cases:
unchanged facts and unchanged records; all five purposes and altered inventories; actual
queued work and key changes; time limits; denied roles and modes; and a concurrent change
while waiting for the audit head. The race observes a real PostgreSQL lock wait, proves the
key row was not locked first, changes the key on another connection and receives SQLSTATE 40001. A new transaction refuses the stale request; fresh preparation succeeds.

The absent-function failure is preserved. The affected run passed 25 tests in four files,
followed by typecheck and lint. These are focused local checks, not complete lifecycle,
release, native Linux or deployment evidence.
