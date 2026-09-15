-- A request can fail before any snapshot exists. Do not invent snapshot evidence
-- to make that terminal state representable. Running/succeeded and post-snapshot
-- failed records keep their original complete snapshot requirements.
alter table public.export_requests drop constraint export_requests_snapshot_ck;
alter table public.export_requests add constraint export_requests_snapshot_ck check (
  coalesce((state in ('running','succeeded','failed')
    and snapshot_manifest is not null
    and octet_length(snapshot_manifest) between 2 and 10485760
    and boardagent_hash_is_sha256(snapshot_sha256)
    and started_at is not null),false)
  or (state='failed' and snapshot_manifest is null
      and snapshot_sha256 is null and started_at is null)
  or state not in ('running','succeeded','failed')
);
