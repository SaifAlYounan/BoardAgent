-- BoardAgent Phase 4 / group 67: full confirmed export surface and disposition authority.

create or replace function public.boardagent_assert_export_authority(
  candidate_export_type text,
  candidate_board_id uuid,
  candidate_exact_origin text
)
returns table(
  organization_id uuid,
  member_id uuid,
  client_id uuid,
  token_jti uuid,
  recent_auth_at text
)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  context_organization uuid;
  context_member uuid;
  context_client uuid;
  context_token uuid;
  authenticated_at timestamptz;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or candidate_export_type not in ('audit_chain','system_data') then
    raise exception 'export authority requires a managed request transaction and export type'
      using errcode='25000';
  end if;
  context_organization := public.boardagent_context_uuid('boardagent.organization_id');
  context_member := public.boardagent_context_uuid('boardagent.member_id');
  context_client := public.boardagent_context_uuid('boardagent.client_id');
  context_token := public.boardagent_context_uuid('boardagent.token_jti');
  select session.last_authenticated_at into strict authenticated_at
    from public.access_token_records as token
    join public.oauth_clients as oauth_client on oauth_client.id=token.client_id
    join public.auth_sessions as session on session.id=token.session_id
    join public.members as actor on actor.id=token.member_id
    join public.system_instance as instance on instance.organization_id=token.organization_id
   where token.organization_id=context_organization
     and token.member_id=context_member
     and token.client_id=context_client
     and token.jti=context_token
     and token.revoked_at is null and token.expires_at>transaction_timestamp()
     and (case candidate_export_type
            when 'audit_chain' then 'audit:read'
            else 'secretariat:admin'
          end)=any(token.scope_set)
     and oauth_client.state='active' and actor.state='active'
     and instance.canonical_resource_uri=token.resource_uri
     and session.organization_id=token.organization_id
     and session.member_id=token.member_id
     and session.client_id=token.client_id
     and session.state='authenticated'
     and session.exact_origin=candidate_exact_origin
     and session.expires_at>transaction_timestamp()
     and session.last_authenticated_at>=transaction_timestamp()-interval '15 minutes'
   for update of token,session;

  if candidate_export_type='system_data' then
    if not exists (
         select 1 from public.organization_role_assignments as assignment
          where assignment.organization_id=context_organization
            and assignment.member_id=context_member and assignment.role='admin'
            and assignment.active_from<=transaction_timestamp()
            and (assignment.active_until is null
                 or assignment.active_until>transaction_timestamp())
       )
       or exists (
         select 1 from public.board_memberships as membership
          where membership.organization_id=context_organization
            and membership.member_id=context_member and membership.seat_role='observer'
            and membership.state='active' and membership.active_from<=transaction_timestamp()
            and (membership.active_until is null
                 or membership.active_until>transaction_timestamp())
       )
       or (candidate_board_id is not null
           and (not public.boardagent_context_board_allowed(candidate_board_id)
                or not exists (
                  select 1 from public.boards as board
                   where board.id=candidate_board_id
                     and board.organization_id=context_organization
                     and board.state='active'
                ))) then
      raise exception 'system export requires a nonobserver administrator and an allowed scope'
        using errcode='42501';
    end if;
  elsif candidate_board_id is not null then
    if not public.boardagent_context_board_allowed(candidate_board_id)
       or not exists (
         select 1 from public.board_memberships as membership
          where membership.organization_id=context_organization
            and membership.board_id=candidate_board_id
            and membership.member_id=context_member and membership.seat_role<>'observer'
            and membership.state='active' and membership.active_from<=transaction_timestamp()
            and (membership.active_until is null
                 or membership.active_until>transaction_timestamp())
       ) then
      raise exception 'board audit export requires a current nonobserver seat'
        using errcode='42501';
    end if;
  elsif not exists (
    select 1 from public.organization_role_assignments as assignment
     where assignment.organization_id=context_organization
       and assignment.member_id=context_member and assignment.role in ('admin','secretariat')
       and assignment.active_from<=transaction_timestamp()
       and (assignment.active_until is null or assignment.active_until>transaction_timestamp())
  ) then
    raise exception 'organization audit export requires current organization authority'
      using errcode='42501';
  end if;

  return query select context_organization,context_member,context_client,context_token,
    to_char(authenticated_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
exception
  when no_data_found then
    raise exception 'export requires a live token and authentication no older than 15 minutes'
      using errcode='42501';
end
$$;
alter function public.boardagent_assert_export_authority(text,uuid,text)
  owner to boardagent_migrator;
revoke all on function public.boardagent_assert_export_authority(text,uuid,text) from public;
grant execute on function public.boardagent_assert_export_authority(text,uuid,text)
  to boardagent_server;

grant select,update on public.export_requests,public.export_artifacts,public.jobs
  to boardagent_migrator;
create policy boardagent_migrator_export_surface_jobs
  on public.jobs for all to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_export_surface_artifacts
  on public.export_artifacts for all to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and exists (
      select 1 from public.export_requests as request
       where request.id=export_artifacts.export_request_id
         and request.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    )
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and exists (
      select 1 from public.export_requests as request
       where request.id=export_artifacts.export_request_id
         and request.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    )
  );

create function public.boardagent_export_disposition_snapshot(
  candidate_action text,
  candidate_public_id bytea,
  candidate_exact_origin text
)
returns jsonb
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  request_row public.export_requests%rowtype;
  artifact_row public.export_artifacts%rowtype;
  context_member uuid;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or candidate_action not in ('cancel_export','delete_export_artifact')
     or octet_length(candidate_public_id)<>32 then
    raise exception 'export disposition requires one managed exact request'
      using errcode='25000';
  end if;
  context_member := public.boardagent_context_uuid('boardagent.member_id');
  select request.* into request_row from public.export_requests as request
   where request.public_id=candidate_public_id
     and request.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
     and request.requester_member_id=context_member
   for update;
  if request_row.id is null then
    raise exception 'owned export request is unavailable' using errcode='P0002';
  end if;
  perform 1 from public.boardagent_assert_export_authority(
    request_row.export_type,request_row.board_id,candidate_exact_origin
  );
  select artifact.* into artifact_row from public.export_artifacts as artifact
   where artifact.export_request_id=request_row.id for update;
  if candidate_action='cancel_export' and request_row.state not in ('queued','running') then
    raise exception 'export request is not cancellable' using errcode='55000';
  elsif candidate_action='delete_export_artifact'
        and (request_row.state<>'succeeded' or artifact_row.id is null
             or artifact_row.state<>'ready') then
    raise exception 'ready export artifact is unavailable' using errcode='55000';
  end if;
  return jsonb_build_object(
    'exportRequestId',request_row.id,
    'publicId',rtrim(translate(encode(request_row.public_id,'base64'),'+/','-_'),'='),
    'organizationId',request_row.organization_id,
    'boardId',request_row.board_id,
    'requesterMemberId',request_row.requester_member_id,
    'exportType',request_row.export_type,
    'state',request_row.state,
    'scopeSha256',encode(request_row.scope_sha256,'hex'),
    'artifactId',artifact_row.id,
    'artifactState',artifact_row.state,
    'manifestSha256',case when artifact_row.id is null then null
      else encode(artifact_row.manifest_sha256,'hex') end
  );
end
$$;

create function public.boardagent_apply_export_disposition(
  candidate_action text,
  candidate_public_id bytea,
  candidate_exact_origin text,
  candidate_payload_sha256 bytea,
  candidate_consent_record_id uuid
)
returns table(
  export_request_id uuid,
  public_id bytea,
  organization_id uuid,
  board_id uuid,
  resulting_state text
)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  snapshot jsonb;
  request_id uuid;
  context_organization uuid;
begin
  snapshot := public.boardagent_export_disposition_snapshot(
    candidate_action,candidate_public_id,candidate_exact_origin
  );
  request_id := (snapshot->>'exportRequestId')::uuid;
  context_organization := public.boardagent_context_uuid('boardagent.organization_id');
  if not public.boardagent_hash_is_sha256(candidate_payload_sha256)
     or not exists (
       select 1 from public.consent_records as consent
        where consent.id=candidate_consent_record_id
          and consent.organization_id=context_organization
          and consent.actor_member_id=public.boardagent_context_uuid('boardagent.member_id')
          and consent.action_code=candidate_action
          and consent.target_type='export_request'
          and consent.target_id=request_id
          and consent.payload_sha256=candidate_payload_sha256
          and consent.package_sha256=decode(snapshot->>'scopeSha256','hex')
     ) then
    raise exception 'export disposition consent binding is invalid' using errcode='42501';
  end if;
  if candidate_action='cancel_export' then
    update public.export_requests
       set state='cancelled',completed_at=transaction_timestamp(),row_version=row_version+1
     where id=request_id and state in ('queued','running');
    update public.export_artifacts as artifact set state='quarantined'
     where artifact.export_request_id=request_id and artifact.state='ready';
    update public.jobs
       set state='cancelled',lease_owner=null,lease_expires_at=null,
           completed_at=transaction_timestamp()
     where subject_type='export_request' and subject_id=request_id
       and state in ('queued','retry');
    return query select request_id,candidate_public_id,context_organization,
      (snapshot->>'boardId')::uuid,'cancelled'::text;
  else
    update public.export_artifacts as artifact set state='expired'
     where artifact.export_request_id=request_id and artifact.state='ready';
    update public.export_requests set state='expired',row_version=row_version+1
     where id=request_id and state='succeeded';
    return query select request_id,candidate_public_id,context_organization,
      (snapshot->>'boardId')::uuid,'deletion_queued'::text;
  end if;
end
$$;

do $export_surface_functions$
declare
  function_name regprocedure;
begin
  foreach function_name in array array[
    'public.boardagent_export_disposition_snapshot(text,bytea,text)'::regprocedure,
    'public.boardagent_apply_export_disposition(text,bytea,text,bytea,uuid)'::regprocedure
  ]
  loop
    execute 'alter function '||function_name||' owner to boardagent_migrator';
    execute 'revoke all on function '||function_name||' from public';
    execute 'grant execute on function '||function_name||' to boardagent_server';
  end loop;
end
$export_surface_functions$;
