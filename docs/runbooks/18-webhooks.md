# 18 — Webhooks

**Owners:** deployment administrator enables the capability; each active non-observer
member manages their own endpoint except governed observer self-service. **Purpose:** send
contentless wake-ups without creating an SSRF or governance-data channel.

1. Keep `BOARDAGENT_WEBHOOKS_ENABLED=false` unless the deployment has an explicit need,
   monitoring, egress policy, and security approval.
2. Before enabling, test endpoint parsing, HTTPS enforcement, credentials rejection,
   private/loopback/link-local/reserved IP denial, DNS rebinding, redirect denial, response
   bounds, timeouts, retries, and secret handling with synthetic endpoints.
3. Review the optional network composition below, then set
   `BOARDAGENT_WEBHOOKS_ENABLED=true` in the application environment shared by server and
   worker. Restart through the [runtime runbook](01-runtime-tls-readiness-drain.md), using
   the webhook overlay as well as the deployment's existing overlays, and verify readiness.
4. The member uses `configure_webhook`; show the generated secret only once and store it in
   the client secret store. Use `test_webhook` and then verify the client refetches current
   state instead of trusting the wake-up.
5. Use `rotate_webhook_secret` after exposure or on schedule. Verify the old secret fails.
   Use `disable_webhook` before investigating a suspicious destination.
6. Monitor failures/dead letters and destination DNS/IP changes. Do not include board,
   member, object, title, count, or action content in delivery or logs.

## Optional worker network

The default `compose.yaml` attaches the worker only to the internal `backend` network.
Enabling the application setting alone does not provide the worker with public routing.
After the enablement review, append `-f compose.webhooks.yaml` to the deployment's existing
Compose file list for configuration inspection and subsequent runtime commands. For the
base production profile, inspect:

```sh
docker compose -f compose.yaml -f compose.production.yaml -f compose.webhooks.yaml \
  --profile https config --no-env-resolution
```

Keep any approved recovery overlay in that same file list. The webhook overlay attaches
only `worker` to the dedicated `webhook-egress` bridge. It preserves the internal backend,
adds no published ports, and does not set the application enablement flag. The server
retains its existing `edge` network and its separate database principal; PostgreSQL,
operator and recovery services receive no webhook network attachment. This bridge provides
a route; endpoint restrictions still depend on the application checks and the reviewed
deployment egress policy. Never use `compose.test.yaml` for production webhook routing.

To disable the capability, set the application flag back to `false`, drain the runtime,
and recreate the worker through the runtime runbook with the webhook overlay omitted.
Inspect the resulting configuration and worker attachments to confirm only `backend`
remains. Preserve notification attempts and failure evidence.

## Delivery limits and verification

Endpoint validation has a five-second DNS deadline. Each delivery starts with a fresh
resolution and uses one ten-second budget covering validation, connection attempts, TLS,
and the complete response. The validated snapshot contains at most 16 public addresses.
Immediate fallback stays within that snapshot and budget, and occurs only after a definite
failure to connect to the exact selected address and port. TCP/TLS progress, request
completion, an ambiguous send, or an HTTP response prevents immediate fallback. Redirects
are rejected. The default transport accepts at most 65,536 response body bytes; durable
retry handling remains separate from immediate address fallback.

DNS timeout and cancellation do not establish that an endpoint is unsafe. Unsafe endpoint
validation is permanent; DNS timeout is a retryable delivery failure. Cancelling or
declining a pending member action does not require DNS to succeed. The operating-system
lookup API cannot physically cancel an outstanding lookup; application waiting is bounded
and a late lookup result cannot start a delivery. The ten-second attempt budget excludes
database claim/completion transactions and cannot overcome an event-loop stall.

Static Compose checks and pure resolver/HTTPS mocks verify configuration and application
branches. They do not prove actual DNS, TLS event order, or container routing. Before
deployment enablement, retain separately approved native/container proof using synthetic
destinations, including an unreachable first public address followed by a reachable public
address, certificate and hostname failures, DNS loss, slow/truncated responses, and
cancellation. Verify real TLS and your deployment's network yourself; no live delivery
follows from adding the optional overlay.

## Evidence

Record enablement approval, endpoint canonical form/hash (not credentials), validation and
SSRF test results, secret creation/rotation receipt without the secret, test delivery,
failure history, and disablement. Any unexpected egress is a security incident.
