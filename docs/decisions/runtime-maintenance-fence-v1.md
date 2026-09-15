# Runtime exclusion during key maintenance — 9 September 2026

This implements the process boundary required by the delegated completion instruction.
An operator must stop the server and worker before applying a new key operation. Read-only
preparation and inspection remain available. Retrying an already completed operation can
return its original receipt while replacement processes are running.

The server and worker each acquire a dedicated PostgreSQL session lease before loading
runtime keys. The lease holds one database-wide shared maintenance lock and two random
marker locks on the same backend. SQL0137 requires the conflicting exclusive transaction
lock before inserting any new key-lifecycle operation. If a service or its guarded database
transaction is still active, the operation refuses without changing a key or recording a
completed operation. Startup also refuses while maintenance holds that exclusive lock.
Existing key-specific locks, snapshot revalidation and unfinished-work refusals remain.

A lifetime connection alone would be insufficient: it can die while another pooled
connection is finishing a request. Production server request handling and worker execution
therefore carry the lease identity through asynchronous context. All four database
transaction wrappers and the separate token lookup transaction acquire shared exclusion
until commit and verify the backend's three actual lease locks before proceeding. If the
lifetime connection dies, a transaction that already entered remains protected until it
ends; subsequent transactions from that stale process refuse even if its local notification
of the connection loss were missed. The marker identity is not a secret or an authorization
claim. Database locks provide exclusion; existing role/object/consent rules provide authority.

Loss of the dedicated connection makes the HTTP service unavailable and prevents new worker
claims. Restart is required to acquire a fresh lease and revalidate the configured keys.
A normal pooled idle-connection loss still follows the existing pool recovery behavior.
The worker stops accepting new claims and drains outstanding work before releasing its
lifetime lease. HTTP listener shutdown retains its existing bounded drain. The application
also releases its lease if initialization fails. One connection is reserved inside each
existing process budget: server19pooled+1 dedicated, worker11pooled+1 dedicated.

This is the supported direct-PostgreSQL VPS deployment profile. A transaction-pooling proxy
cannot substitute for the dedicated session. Custom embedding code that bypasses the
production assembly must supply its own equivalent runtime context; invoking a repository
primitive alone does not establish a stopped-process proof. No PostgreSQL owner resistance
or protection against an operator disabling database controls is claimed. Applications gain
no Docker socket, host root or operator credentials.

`tests/integration/runtime-maintenance-fence.postgres.test.ts` exercises eight cases:
real server/worker exclusion and shutdown, refused startup under maintenance, termination of
the actual lease connection while a transaction is in flight, independent SQL refusal of stale
follow-up work, worker drain, live HTTP503/restart and refused worker claims after lease loss.
Existing browser/data-key HTTPS tests also verify exact completed replay with the restarted
application running. Production worker startup and SIGTERM exercise the compiled package.

Initial tests reproduced key changes succeeding while processes were open. The first patched
run passed eight cases but its child-process test loaded stale compiled exports; rebuilding
before testing restored the real worker command. The drain test then reproduced the missing
drain method. A lint correction and an HTTP fixture correction were retained separately:
use the native HTTP helper with the configured proxy Host rather than an incomplete fetch
request. These are recorded failures, not production security findings silently waived.

The operator CLI, protected file staging and custody, full restart/retained-generation restore,
whole-source/native qualification, bounded independent review and synthetic deployment remain
separate completion work. A passing process-boundary test does not install new private files.
