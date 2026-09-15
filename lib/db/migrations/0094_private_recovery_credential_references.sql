-- Existing get_member recovery metadata: no new tool, role, or credential-table grant.
create function public.boardagent_member_recovery_credentials(candidate_member uuid)
returns jsonb language plpgsql stable security definer set search_path=pg_catalog,public
as $$
declare
  org uuid := public.boardagent_context_uuid('boardagent.organization_id');
  actor uuid := public.boardagent_context_uuid('boardagent.member_id');
  token record;
  result jsonb;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
    or org is null or actor is null then
    raise exception 'recovery references require a managed request' using errcode='42501';
  end if;
  select * into token from public.boardagent_resolve_access_token(
    public.boardagent_context_uuid('boardagent.token_jti'));
  if token.organization_id is distinct from org or token.member_id is distinct from actor
    or token.internal_client_id is distinct from public.boardagent_context_uuid('boardagent.client_id')
    or not coalesce('secretariat:admin'=any(token.scope_set),false)
    or not public.boardagent_administrative_member_eligible(actor)
    or not exists(select 1 from public.organization_role_assignments a
      where a.organization_id=org and a.member_id=actor and a.role in ('admin','secretariat')
        and a.active_from<=transaction_timestamp()
        and (a.active_until is null or a.active_until>transaction_timestamp())) then
    return null;
  end if;
  if not exists(select 1 from public.members m where m.organization_id=org
    and m.id=candidate_member and m.state in ('active','pending_activation')) then
    return null;
  end if;
  -- Return only states accepted by existing preserve_named recovery. Each input and
  -- output is bounded; completeness is explicit rather than silently hiding overflow.
  with candidates as (
    (select c.id,'passkey'::text as kind,c.state,c.created_at,c.last_used_at
      from public.webauthn_credentials c where c.organization_id=org
        and c.member_id=candidate_member and c.state='active' order by c.id limit 129)
    union all
    (select c.id,'totp'::text as kind,c.state,c.created_at,null::timestamptz as last_used_at
      from public.totp_credentials c where c.organization_id=org
        and c.member_id=candidate_member and c.state='active' order by c.id limit 129)
  ), page as materialized (
    select * from candidates order by id limit 129
  ), shown as (
    select * from page order by id limit 128
  )
  select jsonb_build_object(
    'complete',not exists(select 1 from page offset 128),
    'items',coalesce((select jsonb_agg(jsonb_build_object(
      'credential_record_id',id,'kind',kind,'state',state,
      'created_at',to_char(created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
      'last_used_at',case when last_used_at is null then null else
        to_char(last_used_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') end
    ) order by id) from shown),'[]'::jsonb)
  ) into result;
  return result;
end
$$;
alter function public.boardagent_member_recovery_credentials(uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_member_recovery_credentials(uuid) from public,boardagent_worker,boardagent_backup;
grant execute on function public.boardagent_member_recovery_credentials(uuid) to boardagent_server;
