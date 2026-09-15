-- Bounded administrative discovery. This read lane has no direct table grants and
-- never returns credential material or an unfiltered authority payload.
create function public.boardagent_administrative_access_page(
  candidate_mode text,
  candidate_board uuid,
  candidate_limit integer,
  candidate_after jsonb
)
returns jsonb language plpgsql stable security definer set search_path=pg_catalog,public
as $$
declare
  org uuid := public.boardagent_context_uuid('boardagent.organization_id');
  actor uuid := public.boardagent_context_uuid('boardagent.member_id');
  token record;
  is_admin boolean;
  envelope jsonb;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
    or org is null or actor is null then
    raise exception 'administrative access is unavailable' using errcode='42501';
  end if;
  if candidate_mode is null or candidate_mode not in ('mine','organization')
    or candidate_limit is null or candidate_limit not between 1 and 100
    or (candidate_board is not null and not public.boardagent_is_uuid_v7(candidate_board)) then
    raise exception 'administrative access input is invalid' using errcode='22023';
  end if;
  if candidate_after is not null and (
    jsonb_typeof(candidate_after) is distinct from 'object'
    or not(candidate_after ?& array['mode','generation','at','id','kind'])
    or candidate_after-array['mode','generation','at','id','kind']<>'{}'::jsonb
    or candidate_after->>'mode' is distinct from candidate_mode
    or coalesce(candidate_after->>'generation','')!~'^[0-9a-f]{64}$'
    or jsonb_typeof(candidate_after->'at') is distinct from 'string'
    or length(candidate_after->>'at') not between 1 and 64
    or jsonb_typeof(candidate_after->'id') is distinct from 'string'
    or not public.boardagent_is_uuid_v7((candidate_after->>'id')::uuid)
    or candidate_after->>'kind' not in ('company_admin_assignment','company_admin_proposal','member_admin_delegation')
  ) then raise exception 'administrative cursor is invalid' using errcode='22023'; end if;
  select * into token from public.boardagent_resolve_access_token(
    public.boardagent_context_uuid('boardagent.token_jti'));
  if token.organization_id is distinct from org or token.member_id is distinct from actor
    or token.internal_client_id is distinct from public.boardagent_context_uuid('boardagent.client_id')
    or not coalesce('secretariat:admin'=any(token.scope_set),false)
    or not exists(select 1 from public.members m where m.organization_id=org and m.id=actor
      and m.state='active' and m.member_kind='human') then
    raise exception 'administrative access is unavailable' using errcode='42501';
  end if;
  is_admin := 'admin'=any(token.roles) and public.boardagent_administrative_member_eligible(actor);
  if candidate_mode='organization' and not is_admin then
    raise exception 'administrative access is unavailable' using errcode='42501';
  end if;
  if candidate_board is not null and (
    not exists(select 1 from public.boards b where b.organization_id=org and b.id=candidate_board)
    or (candidate_mode='mine' and not(candidate_board::text=any(token.board_ids)))
  ) then raise exception 'administrative access is unavailable' using errcode='42501'; end if;

  with visible_records as materialized (
    select a.created_at as at,a.id,'company_admin_assignment'::text as kind,
      jsonb_build_object(
        'record_type','company_admin_assignment','record_id',a.id,'row_version','1',
        'board_id',null,'state','active','active_from',a.active_from,'expires_at',a.active_until,
        'actor',case when issuer.id is null then null else jsonb_build_object('member_id',issuer.id,'display_name',issuer.display_name) end,
        'target',jsonb_build_object('member_id',m.id,'display_name',m.display_name),
        'authority_evidence','[]'::jsonb
      ) as item
    from public.organization_role_assignments a
    join public.members m on m.organization_id=a.organization_id and m.id=a.member_id
    left join public.company_admin_proposals p on p.organization_id=a.organization_id and p.granted_assignment_id=a.id
    left join public.members issuer on issuer.organization_id=p.organization_id and issuer.id=p.issuer_member_id
    where a.organization_id=org and a.role='admin' and candidate_board is null
      and (candidate_mode='organization' or a.member_id=actor)
      and a.active_from<=transaction_timestamp() and (a.active_until is null or a.active_until>transaction_timestamp())
      and public.boardagent_administrative_member_eligible(a.member_id)
    union all
    select p.created_at,p.id,'company_admin_proposal'::text,
      jsonb_build_object(
        'record_type','company_admin_proposal','record_id',p.id,'row_version',p.row_version::text,
        'board_id',null,'operation',p.operation,
        'state',case when p.issuer_identity_generation=issuer.identity_generation
          and p.target_identity_generation=target.identity_generation and p.target_member_version=target.row_version
          and public.boardagent_administrative_member_eligible(issuer.id)
          and public.boardagent_administrative_member_eligible(target.id)
          and exists(select 1 from public.organization_role_assignments a where a.organization_id=org
            and a.id=p.issuer_assignment_id and a.member_id=issuer.id and a.role='admin'
            and a.active_from<=transaction_timestamp() and (a.active_until is null or a.active_until>transaction_timestamp()))
          and not exists(select 1 from public.organization_role_assignments a where a.organization_id=org
            and a.member_id=target.id and a.role='admin' and a.active_from<=transaction_timestamp()
            and (a.active_until is null or a.active_until>transaction_timestamp()))
          then 'pending' else 'unavailable' end,
        'active_from',p.created_at,'expires_at',p.expires_at,
        'actor',jsonb_build_object('member_id',issuer.id,'display_name',issuer.display_name),
        'target',jsonb_build_object('member_id',target.id,'display_name',target.display_name),
        'authority_evidence','[]'::jsonb
      )
    from public.company_admin_proposals p
    join public.members issuer on issuer.organization_id=p.organization_id and issuer.id=p.issuer_member_id
    join public.members target on target.organization_id=p.organization_id and target.id=p.target_member_id
    where p.organization_id=org and p.state='pending' and p.expires_at>transaction_timestamp()
      and candidate_board is null
      and (candidate_mode='organization' or p.target_member_id=actor or p.issuer_member_id=actor)
    union all
    select d.created_at,d.id,'member_admin_delegation'::text,
      jsonb_build_object(
        'record_type','member_admin_delegation','record_id',d.id,'row_version',d.row_version::text,
        'board_id',d.board_id,'state','active','active_from',d.created_at,'expires_at',d.expires_at,
        'actor',jsonb_build_object('member_id',issuer.id,'display_name',issuer.display_name),
        'target',jsonb_build_object('member_id',target.id,'display_name',target.display_name),
        'authority_evidence',coalesce((
          select jsonb_agg(c.value order by c.ordinality)
          from jsonb_array_elements(d.authority_evidence) with ordinality as c(value,ordinality)
          join public.document_versions v on v.id=(c.value->>'document_version_id')::uuid
            and v.organization_id=d.organization_id and v.board_id=d.board_id
            and encode(v.sha256,'hex')=c.value->>'sha256'
          where public.boardagent_document_permission(v.document_id,'read')
        ),'[]'::jsonb)
      )
    from public.member_admin_delegations d
    join public.members issuer on issuer.organization_id=d.organization_id and issuer.id=d.issuer_member_id
    join public.members target on target.organization_id=d.organization_id and target.id=d.member_id
    where d.organization_id=org and (candidate_mode='organization' or d.member_id=actor)
      and (candidate_board is null or d.board_id=candidate_board)
      and public.boardagent_member_admin_delegation_effective(d.id)
      and public.boardagent_administrative_member_eligible(d.member_id)
  ), generation as (
    -- This is an internal cursor invalidation fingerprint, not a canonical
    -- governance/evidence hash. Bind the entire authorized projection, including
    -- citation visibility, and the caller's current identity/membership versions.
    select encode(sha256(convert_to(
      coalesce((select string_agg(r.kind||':'||r.id::text||':'||r.item::text,chr(10) order by r.at,r.kind,r.id) from visible_records r),'')
      ||chr(10)||coalesce((select m.identity_generation::text||':'||m.onboarding_generation::text||':'||m.row_version::text from public.members m where m.organization_id=org and m.id=actor),'')
      ||chr(10)||coalesce((select string_agg(s.id::text||':'||s.entitlement_generation::text||':'||s.state||':'||s.is_secretary::text||':'||s.seat_role||':'||s.active_from::text||':'||coalesce(s.active_until::text,''),chr(10) order by s.id)
        from public.board_memberships s where s.organization_id=org and s.member_id=actor),''),
      'UTF8')),'hex') as value
  ), page as (
    select r.* from visible_records r
    where candidate_after is null or (r.at,r.kind,r.id)>(
      (candidate_after->>'at')::timestamptz,candidate_after->>'kind',(candidate_after->>'id')::uuid)
    order by r.at,r.kind,r.id limit candidate_limit+1
  )
  select jsonb_build_object('generation',g.value,'rows',coalesce((
    select jsonb_agg(jsonb_build_object('item',p.item,'at',p.at,'kind',p.kind,'id',p.id) order by p.at,p.kind,p.id) from page p
  ),'[]'::jsonb)) into envelope from generation g;
  if candidate_after is not null and candidate_after->>'generation' is distinct from envelope->>'generation' then
    raise exception 'administrative cursor is stale; restart listing' using errcode='22023';
  end if;
  return envelope;
end
$$;
alter function public.boardagent_administrative_access_page(text,uuid,integer,jsonb) owner to boardagent_migrator;
revoke all on function public.boardagent_administrative_access_page(text,uuid,integer,jsonb) from public;
grant execute on function public.boardagent_administrative_access_page(text,uuid,integer,jsonb) to boardagent_server;
