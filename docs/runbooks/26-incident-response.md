# 26 — Incident response

**Owner:** named security contact, supported by deployment administrator, secretariat, and
the project owner. **Purpose:** contain, preserve evidence, recover, and communicate without creating
new governance/data harm.

## Triage and contain

1. Open a private incident record with UTC detection time, reporter, deployment, suspected
   assets, and confidentiality class. Do not copy board content/secrets unnecessarily.
2. Classify: client/token, identity, key, host/container, database, DNS/TLS, webhook/egress,
   audit/evidence, availability, or recovery compromise.
3. Preserve volatile logs, image/container IDs, config digests, key IDs, audit/checkpoint
   head, sessions/clients, jobs, backups/WAL, and clock state. Hash exported evidence.
4. Stop traffic or affected capability when integrity/authority is uncertain. Use the
   dedicated token, identity, key, webhook, outage, or recovery runbook; do not alter rows or
   evidence directly.

## Scope and recover

1. Establish the exposure window and enumerate affected principals, clients, actions,
   signatures, exports, destinations, keys, and backups by canonical identifiers.
2. Verify audit/checkpoint/certificate continuity with independent trust material. A valid
   signature under a suspected key is not automatically trustworthy.
3. Fix through a reviewed source/config/key change, rerun the corresponding attacks and
   full net, rebuild images, and restore into isolation if persistent state is suspect.
4. Reopen only after containment verification, readiness, synthetic journeys, recovery
   evidence, and incident-owner approval.

## Communication and closure

Secretariat determines governance-record consequences; deployment owner handles service
facts; security contact controls sensitive disclosure; the project owner handles frozen
design implications. State uncertainty plainly and do not claim no impact without evidence.

Record immutable timeline, decisions/owners, evidence hashes, containment, affected-object
inventory, notifications, root cause, correction, regression proof, recovery receipt,
residual risk, and dated follow-ups. Never delete incident evidence to make a release green.
