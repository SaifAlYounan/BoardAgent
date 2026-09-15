# Key maintenance work inventory — 9 September 2026

This implements a read-only prerequisite under the actual
[operational completion instruction](operational-completion-instruction-2026-09-08.md).
It does not stop a process, change a key, prove archive custody or implement a replacement.

SQL0128 `boardagent_inspect_key_maintenance_work` calls SQL0127's declared-key inventory in
the same serializable read-only operator transaction. The exact instance, organization,
key and database policy checks therefore apply to both. Only the migrator can call it;
server, worker and backup roles remain denied even with a claimed bootstrap scope.

Sixteen fixed query groups report counts and sorted SHA-256 row chains. Private row
contents remain inside PostgreSQL. Joined vote/stage facts include both records, so a
changed workflow state changes the digest. Formatting and ordering are fixed, and the
typed wrapper excludes only observation time from its canonical state digest. A maximum
of one million work-reference occurrences is checked before hashing each group; overlap
between groups counts twice. This is a preparation bound, not a performance qualification.

| Facts                                                      | Scope and meaning                                                                                                                               |
| ---------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| Leased jobs and notifications                              | All leased rows, including expired leases awaiting reconciliation; absence alone does not prove the process has stopped.                        |
| Unfinished jobs                                            | Queued and retry rows, including typed payload bytes in the digest; this does not claim each queued job can safely switch keys.                 |
| Running and pending exports                                | Running, or confirmed/queued export requests, independently of an artifact's eventual key FK.                                                   |
| Closing votes                                              | All closing votes for an evidence-key inspection, including incomplete state without an outcome.                                                |
| Unfinished vote outcomes                                   | The selected signer is pinned to a closing vote or an outcome without its certificate.                                                          |
| Live vote-close stages                                     | Selected signer, active stage and unexpired confirmation; the complete joined material/stage participates in the hash.                          |
| Pending and active TOTP                                    | Separate unfinished enrollment and usable factors for the selected data key.                                                                    |
| Active webhooks and contact points                         | Current direct dependencies on the selected key. Historical rewrap lineage still needs implementation.                                          |
| Browser sessions, authorization requests and action stages | Conservatively includes pending/active state for a browser-key inspection; browser rows do not carry a key FK.                                  |
| Affected refresh families                                  | All active families for a browser key; for an OAuth key, active families linked through any retained access-token record issued by that signer. |

No UUID-string search through arbitrary board content is treated as a cryptographic
dependency. Retained envelopes, archive files and off-host backup/WAL generations still
need their own explicit inventory and file checks. These facts must be revalidated by the
future protected application transaction; a stale preparation is not authorization.

Executing tests in `tests/integration/key-maintenance-work.postgres.test.ts` cover all
groups' shapes across five purposes, real queued/leased/retry transitions with zero direct
key references, real TOTP enrollment and activation, secret omission, stable display
settings, denied runtime roles, writable transactions and wrong targets. Those tests do
not yet execute positive vote/export/browser maintenance transitions. Initial missing
function failure and first passing case are retained. The expanded run passed 26 tests in
four files plus typecheck/lint, including SQL0127 inventory and migration guards.

Full lifecycle, rewrap/revocation, interrupted application, stale runtime, actual restart
and old/new encrypted recovery proof remain unfinished. The three documentation closure
failures recorded with the maintenance registry are also still open. No release, native
Linux, deployment or human acceptance pass is claimed here.
