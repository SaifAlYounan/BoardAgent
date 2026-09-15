# 33 — Persistent local installation for acceptance

**Owner:** the deployment administrator of the machine that hosts the instance. The setup
administrator, secretary and directors are application accounts created afterwards; none
of them needs host access.

**Purpose:** run one durable BoardAgent instance on a single machine, from the exact
qualified release images, with HTTPS at `https://localhost`, the worker on and retained
data, so that real human acceptance (SR-102) can be exercised by people using separate
browser profiles and separate MCP client configurations. This is the same production
composition as [DEPLOY.md](../../DEPLOY.md), pointed at `localhost`; it is not a
development shortcut.

**Status:** this procedure has not yet been exercised end to end on this source tree.
Record your own receipt when you run it, and report any step that does not match.

## Preconditions

- The release is qualified: the `verify:private-beta` receipt for the exact commit reads
  `passed`, and the three images were built from that commit
  (`scripts/src/build-release-image.ts`; tags and digests in the receipt).
- Docker with Compose v2 runs; nothing else listens on 443 or 8787.
- A configuration directory outside the repository, mode `0700`, holding the production
  environment file, the secret directories described in DEPLOY.md, the reviewed
  `bootstrap.json` under a `10001:10001` handoff directory, the bootstrap receipt and
  the Caddy root certificate. It is never committed and never quoted in a report.

## Procedure

1. Write the production environment file from `.env.production.example`:
   `BOARDAGENT_ENV=production`, `BOARDAGENT_PUBLIC_BASE_URL=https://localhost`,
   `BOARDAGENT_TRUSTED_PROXY_HOPS=1`, `CADDY_DOMAIN=localhost`, and `RELEASE_IMAGE`,
   `POSTGRES_IMAGE` and `CADDY_IMAGE` set to the qualified tags. Create the per-purpose
   secret files exactly as DEPLOY.md describes; there is no development master secret in
   this profile. Leave `BOARDAGENT_ORGANIZATION_ID` at the placeholder until bootstrap
   returns the real one.
2. Use a dedicated Compose project so that no other local stack shares its volumes, and
   always pass the production overlay after the base file:

   ```sh
   docker compose -p boardagent-local --env-file /absolute/config/app.env \
     -f compose.yaml -f compose.production.yaml \
     --profile initialize up application-secret-init postgres database-initializer
   ```

   Require the initializer to exit 0 (every migration applied, principals provisioned).

3. Prepare `bootstrap.json` from `docs/examples/bootstrap.example.json`: the setup
   administrator's display name and contact, and the first board seat with a voting
   weight of at least 1 (bootstrap refuses weight 0; the secretary's non-voting seat is
   created later through the surface). The canonical MCP resource is derived from
   `BOARDAGENT_PUBLIC_BASE_URL`; do not add it to the file. Copy the reviewed file into a
   new `10001:10001 0700` handoff directory as DEPLOY.md shows, mount it read-only and
   run bootstrap once:

   ```sh
   docker compose -p boardagent-local --env-file /absolute/config/app.env \
     -f compose.yaml -f compose.production.yaml \
     --profile operator run --rm \
     --volume /absolute/operator-input:/operator-input:ro \
     operator bootstrap /operator-input/bootstrap.json > /absolute/config/bootstrap-receipt.json
   ```

   The receipt carries the one-use enrollment link: treat it as a credential. Put the
   returned organization UUID into the environment file.

4. Start the runtime and the HTTPS edge, trust Caddy's local root certificate in the
   login keychain only, then verify liveness and readiness:

   ```sh
   docker compose -p boardagent-local --env-file /absolute/config/app.env \
     -f compose.yaml -f compose.production.yaml \
     --profile https up -d server worker caddy
   curl --fail --cacert /absolute/config/caddy-root.crt https://localhost/health/live
   curl --fail --cacert /absolute/config/caddy-root.crt https://localhost/health/ready
   ```

   Readiness must be true before any login. An unhealthy worker keeps readiness false;
   fix that first (runbook 17).

5. First activation is a human act (runbook 02): open the enrollment link in the
   administrator's browser profile, register the passkey, confirm the ten-minute code
   with `operator bootstrap activate-first`. If the code lapses, do not run bootstrap
   again: use `operator bootstrap reissue-first-activation REQUEST.json` once
   (runbook 32), re-prove with the same passkey, confirm the fresh code.
6. Connect the administrator's MCP client, then enroll the secretary and the directors
   through the surface, one browser profile and one client configuration per role
   (runbook 03).
7. Keep the instance. Never run `down -v`. Stop and start with `stop` / `start` on the
   same project. Take a backup before any upgrade (runbook 22) and read the retained
   state with `operator inspect-pilot-state` after each session.

## Record

The receipt for this runbook records the Compose project name, image tags and digests,
the organization UUID, the readiness output, the timestamp of the human first
activation, and the pilot-state inventory. It never records secrets, the enrollment or
restart links, activation codes, cookies or tokens. This receipt and the
`boardagent.human-acceptance-receipt.v1` document written after the role sessions are the
evidence that SR-102 was exercised by a real person on this exact release.
