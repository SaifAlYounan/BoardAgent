-- BoardAgent task creation: expose only a locked exact minutes source to the request role.

create function boardagent_lock_task_source(
  candidate_board_id uuid,
  candidate_minutes_id uuid,
  candidate_minutes_version_id uuid
)
returns table(
  meeting_id uuid,
  minutes_sha256 bytea
)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or not boardagent_context_board_allowed(candidate_board_id)
     or not boardagent_secretariat_for_board(candidate_board_id) then
    raise exception 'task source lock requires the managed secretariat request context'
      using errcode = '25000';
  end if;
  return query
    select minutes.meeting_id,version.canonical_sha256
      from minutes
      join minutes_versions as version
        on version.minutes_id=minutes.id
       and version.id=candidate_minutes_version_id
     where minutes.organization_id=boardagent_context_uuid('boardagent.organization_id')
       and minutes.board_id=candidate_board_id
       and minutes.id=candidate_minutes_id
     -- The minutes version is immutable. Lock the mutable minutes root while reading the
     -- version hash; attempting to row-lock the immutable version would require an UPDATE
     -- policy that the request boundary deliberately does not possess.
     for key share of minutes;
end
$$;

alter function boardagent_lock_task_source(uuid,uuid,uuid)
  owner to boardagent_migrator;
revoke all on function boardagent_lock_task_source(uuid,uuid,uuid) from public;
grant execute on function boardagent_lock_task_source(uuid,uuid,uuid)
  to boardagent_server;
