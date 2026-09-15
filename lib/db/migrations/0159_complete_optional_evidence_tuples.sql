-- Optional evidence references must be wholly absent or wholly present.
-- The historical hash/type checks remain in force, but a STRICT hash helper
-- returns SQL NULL for SQL NULL input, which alone does not fail a CHECK.
-- These validated constraints refuse malformed history without rewriting it.

alter table public.minutes_versions
  add constraint minutes_versions_transcript_tuple_ck
  check (
    (transcript_version_id is null and transcript_sha256 is null)
    or (transcript_version_id is not null and transcript_sha256 is not null)
  );

alter table public.tasks
  add constraint tasks_minutes_source_tuple_ck
  check (
    (source_meeting_id is null and source_minutes_id is null
      and source_minutes_version_id is null and source_minutes_sha256 is null
      and source_locator is null)
    or (source_meeting_id is not null and source_minutes_id is not null
      and source_minutes_version_id is not null and source_minutes_sha256 is not null
      and source_locator is not null)
  );
