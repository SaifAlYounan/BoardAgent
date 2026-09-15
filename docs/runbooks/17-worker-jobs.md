# 17 — Worker and jobs

**Owner:** deployment administrator. **Purpose:** operate the least-privilege worker and
distinguish queued, leased, completed, retryable, and dead-lettered work.

The worker handles typed jobs including notification delivery, audit checkpoints, vote
deadline/close recovery, certificate issuance recovery, exports, temporary artifact
cleanup, feed maintenance, task due projection, operational retention, backup health, and
clock/heartbeat state. A job payload is not authority; the worker rechecks exact type,
organization/object binding, lifecycle, lease, and database role.

1. Check server readiness, worker heartbeat/lease state, queue depth by type/status, oldest
   age, retry counts, dead letters, and database/clock health.
2. For backlog, identify the first failing typed job and its non-secret identifiers. Inspect
   the canonical event/receipt rather than replaying an arbitrary payload.
3. Fix the dependency or code/config cause. Allow bounded lease expiry/retry or use the
   verified recovery path. Never forge a completed state, move a job by direct SQL, or
   duplicate a binding act to make progress.
4. Verify idempotent replay produces one outcome and one logical evidence chain. For a
   certificate/close recovery, compare exact package and outcome hashes.
5. Keep readiness closed if critical job/heartbeat/backup/clock thresholds are violated.

Record queue metrics, job type/ID/object, lease/retry history, root cause, repair version,
replay result, resulting audit/receipt ID, and readiness restoration. Persistent growth or
unknown job types is an incident and release blocker.
