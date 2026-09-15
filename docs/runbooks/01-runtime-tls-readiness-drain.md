# 01 — Runtime, TLS, readiness, and drain

**Owner:** deployment administrator. **Purpose:** start, check, drain, and stop the verified
single-VPS profile without mistaking liveness for readiness.

## Start

1. Confirm the approved source digest and immutable application/PostgreSQL/Caddy image IDs.
2. Render and inspect the merged base and production Compose configuration.
3. Confirm DNS, ports 80/443, host clock, secret mounts, volumes, and internal database
   network. PostgreSQL must have no published port.
4. Start `server`, `worker`, and the `https` profile's Caddy service using the exact command
   in `DEPLOY.md`.
5. Require both `/health/live` and `/health/ready` to return success through the public HTTPS
   origin. Check that HTTP does not expose application traffic outside the intended edge.
6. Perform synthetic `whoami` and one entitled read using a designated test principal.

## Drain and stop

1. Record current job/backup/export state and prevent new edge traffic.
2. Wait for in-flight MCP requests and confirmation rounds to finish or expire. Do not
   preserve an H-action stage across a maintenance boundary.
3. Confirm no migration, backup snapshot, restore receipt, or key ceremony is running.
4. Send the normal Compose stop; allow the configured 30-second grace period.
5. Verify server/worker exit, then stop Caddy. Stop PostgreSQL last only when required.

## Evidence and escalation

Record image IDs, DNS/TLS certificate identity, health responses, synthetic principal/tool,
container start/stop times, graceful-exit status, and any unfinished work. Live-but-unready,
clock failure, migration mismatch, repeated restart, or stale worker health blocks traffic
and escalates to the deployment administrator/security contact as appropriate.
