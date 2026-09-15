# 23 — Migrations, upgrade, and rollback

**Owner:** deployment administrator; the project owner and the security owner when compatibility or frozen behavior
changes. **Purpose:** advance schema/application together and recover without improvised
down-migrations.

## Prepare

1. Freeze one candidate source tree. Run required T0–T9 (and T10 for public release), build
   all images from that tree, scan them, and record immutable IDs/digests.
2. Compare generated registry, migration list/digests, dependencies, environment schema,
   Compose topology, and known limitations with the running release.
3. Produce and verify fresh logical backup, physical base backup, WAL continuity, and
   isolated restore. Record the exact pre-upgrade image IDs/migration head.
4. Define go/no-go checks, maintenance communication, forward-fix owner, and recovery/cutover
   decision point.

## Execute

1. Drain traffic using runbook 01; stop server/worker but keep PostgreSQL/recovery controls.
2. Run the candidate `database-initializer` once with owner/migrator provisioning inputs.
   Require the exact applied-migration receipt. A checksum mismatch or partial result stops
   the upgrade.
3. Start candidate server and worker together. Require readiness and verify synthetic
   onboarding/read, confirmation cancellation, vote/certificate, export, worker, and backup
   journeys appropriate to the change.
4. Reopen edge traffic only after the go/no-go owner signs the observed checks. Record the
   post-upgrade source/image/migration/registry state.

## Rollback/forward fix

Migrations are append-only and forward-fix by default. Do not edit an applied migration,
run an older binary on an unproven newer schema, or improvise a reverse SQL script. For an
application-only fault compatible with the schema, use only a pairing explicitly proven in
release evidence. Otherwise restore the pre-upgrade recovery set to an isolated target,
verify it fully, quiesce writes, and execute a deliberate cutover under the incident plan.

Record backups/restores, before/after digests, migration receipt, synthetic results,
readiness, traffic times, failures, chosen forward-fix/restore decision, data-loss window,
and final owner approval.
