-- BoardAgent confirmed document circulation, ACL and retention lifecycle authority.

grant insert on
  circulation_recipients,
  deletion_tombstones,
  document_access_grants,
  document_circulations,
  document_exclusions,
  retention_snapshots
to boardagent_server;
grant select on document_access_grants,document_circulations,document_exclusions
  to boardagent_server;
grant update(active_until) on document_exclusions to boardagent_server;
grant select on circulation_recipients,document_circulations to boardagent_migrator;

create unique index circulation_recipients_one_version_per_member_uq
  on circulation_recipients(member_id,document_version_id);

create function boardagent_document_secretary_for_board(candidate_board uuid)
returns boolean
language sql
stable
security definer
set search_path=pg_catalog,public
as $$
  select boardagent_communication_actor_ready(candidate_board,'secretariat:admin')
     and exists (
       select 1 from board_memberships as membership
        where membership.organization_id=boardagent_context_uuid('boardagent.organization_id')
          and membership.board_id=candidate_board
          and membership.member_id=boardagent_context_uuid('boardagent.member_id')
          and membership.state='active'
          and membership.active_from<=transaction_timestamp()
          and (membership.active_until is null
               or membership.active_until>transaction_timestamp())
          and (
            membership.is_secretary
            or exists (
              select 1 from organization_role_assignments as assignment
               where assignment.organization_id=membership.organization_id
                 and assignment.member_id=membership.member_id
                 and assignment.role='secretariat'
                 and assignment.active_from<=transaction_timestamp()
                 and (assignment.active_until is null
                      or assignment.active_until>transaction_timestamp())
            )
          )
     )
$$;
alter function boardagent_document_secretary_for_board(uuid)
  owner to boardagent_migrator;
revoke all on function boardagent_document_secretary_for_board(uuid) from public;
grant execute on function boardagent_document_secretary_for_board(uuid)
  to boardagent_server;

create function boardagent_document_admin_for_board(candidate_board uuid)
returns boolean
language sql
stable
security definer
set search_path=pg_catalog,public
as $$
  select boardagent_communication_actor_ready(candidate_board,'secretariat:admin')
     and exists (
       select 1 from board_memberships as membership
       join organization_role_assignments as assignment
         on assignment.organization_id=membership.organization_id
        and assignment.member_id=membership.member_id
        and assignment.role='admin'
        and assignment.active_from<=transaction_timestamp()
        and (assignment.active_until is null
             or assignment.active_until>transaction_timestamp())
        where membership.organization_id=boardagent_context_uuid('boardagent.organization_id')
          and membership.board_id=candidate_board
          and membership.member_id=boardagent_context_uuid('boardagent.member_id')
          and membership.state='active'
          and membership.active_from<=transaction_timestamp()
          and (membership.active_until is null
               or membership.active_until>transaction_timestamp())
     )
$$;
alter function boardagent_document_admin_for_board(uuid)
  owner to boardagent_migrator;
revoke all on function boardagent_document_admin_for_board(uuid) from public;
grant execute on function boardagent_document_admin_for_board(uuid)
  to boardagent_server;

create policy boardagent_server_document_access_grants_lifecycle_select
  on document_access_grants for select to boardagent_server
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and boardagent_secretariat_for_board(board_id)
  );
create policy boardagent_server_document_access_grants_lifecycle
  on document_access_grants for insert to boardagent_server
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and granted_by=boardagent_context_uuid('boardagent.member_id')
    and boardagent_secretariat_for_board(board_id)
  );

create policy boardagent_server_document_exclusions_lifecycle_select
  on document_exclusions for select to boardagent_server
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and boardagent_secretariat_for_board(board_id)
  );
create policy boardagent_server_document_exclusions_lifecycle_insert
  on document_exclusions for insert to boardagent_server
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and created_by=boardagent_context_uuid('boardagent.member_id')
    and boardagent_secretariat_for_board(board_id)
  );
create policy boardagent_server_document_exclusions_lifecycle_update
  on document_exclusions for update to boardagent_server
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and boardagent_secretariat_for_board(board_id)
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and boardagent_secretariat_for_board(board_id)
  );

drop policy boardagent_server_scope on document_circulations;
create policy boardagent_server_document_circulations_lifecycle_select
  on document_circulations for select to boardagent_server
  using (
    organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
  );
create policy boardagent_migrator_document_circulations_lifecycle_select
  on document_circulations for select to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and boardagent_document_secretary_for_board(board_id)
  );
create policy boardagent_server_document_circulations_lifecycle_insert
  on document_circulations for insert to boardagent_server
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and circulated_by=boardagent_context_uuid('boardagent.member_id')
    and boardagent_document_secretary_for_board(board_id)
  );

create policy boardagent_server_circulation_recipients_lifecycle
  on circulation_recipients for insert to boardagent_server
  with check (
    exists (
      select 1 from document_circulations as circulation
       where circulation.id=circulation_id
         and circulation.organization_id=boardagent_context_uuid('boardagent.organization_id')
         and boardagent_context_board_allowed(circulation.board_id)
         and circulation.circulated_by=boardagent_context_uuid('boardagent.member_id')
         and boardagent_document_secretary_for_board(circulation.board_id)
    )
  );
create policy boardagent_migrator_circulation_recipients_lifecycle_select
  on circulation_recipients for select to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and exists (
      select 1 from document_circulations as circulation
       where circulation.id=circulation_id
         and circulation.organization_id=boardagent_context_uuid('boardagent.organization_id')
         and boardagent_context_board_allowed(circulation.board_id)
         and boardagent_document_secretary_for_board(circulation.board_id)
    )
  );

drop policy boardagent_server_scope on retention_snapshots;
create policy boardagent_server_document_retention_snapshot_insert
  on retention_snapshots for insert to boardagent_server
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=boardagent_context_uuid('boardagent.organization_id')
    and board_id is not null
    and boardagent_context_board_allowed(board_id)
    and object_type='document'
    and boardagent_document_admin_for_board(board_id)
  );

drop policy boardagent_server_scope on deletion_tombstones;
create policy boardagent_server_document_deletion_tombstone_insert
  on deletion_tombstones for insert to boardagent_server
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=boardagent_context_uuid('boardagent.organization_id')
    and board_id is not null
    and boardagent_context_board_allowed(board_id)
    and object_type='document'
    and actor_member_id=boardagent_context_uuid('boardagent.member_id')
    and boardagent_document_admin_for_board(board_id)
  );

create function boardagent_lock_document_lifecycle(
  candidate_document_id uuid,
  candidate_board_id uuid,
  candidate_version_id uuid
)
returns table(
  document_id uuid,
  organization_id uuid,
  board_id uuid,
  title text,
  document_state text,
  row_version bigint,
  version_id uuid,
  version_number integer,
  document_sha256 bytea,
  actor_is_secretary boolean,
  actor_is_admin boolean
)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request' then
    raise exception 'document lifecycle lock requires a managed request transaction'
      using errcode='25000';
  end if;
  return query
    select document.id,
           document.organization_id,
           document.board_id,
           document.title,
           document.state,
           document.row_version,
           version.id,
           version.version,
           version.sha256,
           boardagent_document_secretary_for_board(document.board_id),
           boardagent_document_admin_for_board(document.board_id)
      from documents as document
      join document_versions as version
        on version.document_id=document.id
       and version.id=coalesce(candidate_version_id,document.current_version_id)
      join board_memberships as membership
        on membership.organization_id=document.organization_id
       and membership.board_id=document.board_id
       and membership.member_id=boardagent_context_uuid('boardagent.member_id')
     where document.id=candidate_document_id
       and document.organization_id=boardagent_context_uuid('boardagent.organization_id')
       and (candidate_board_id is null or document.board_id=candidate_board_id)
       and boardagent_context_board_allowed(document.board_id)
       and boardagent_secretariat_for_board(document.board_id)
       and membership.state='active'
       and membership.active_from<=transaction_timestamp()
       and (membership.active_until is null
            or membership.active_until>transaction_timestamp())
     for update of document;
end
$$;
alter function boardagent_lock_document_lifecycle(uuid,uuid,uuid)
  owner to boardagent_migrator;
revoke all on function boardagent_lock_document_lifecycle(uuid,uuid,uuid) from public;
grant execute on function boardagent_lock_document_lifecycle(uuid,uuid,uuid)
  to boardagent_server;

create function boardagent_lock_document_recipients(
  candidate_document_id uuid,
  candidate_version_id uuid,
  candidate_member_ids uuid[]
)
returns table(
  member_id uuid,
  entitlement_generation bigint,
  can_read boolean,
  already_circulated boolean
)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  source_board_id uuid;
  source_organization_id uuid;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or candidate_member_ids is null
     or cardinality(candidate_member_ids) not between 1 and 1000
     or exists (select 1 from unnest(candidate_member_ids) as requested(id) where id is null)
     or (select count(distinct id) from unnest(candidate_member_ids) as requested(id))
          <> cardinality(candidate_member_ids) then
    raise exception 'document recipient lock requires one through 1000 exact recipients'
      using errcode='22023';
  end if;
  select document.organization_id,document.board_id
    into source_organization_id,source_board_id
    from documents as document
    join document_versions as version
      on version.document_id=document.id and version.id=candidate_version_id
   where document.id=candidate_document_id
     and document.organization_id=boardagent_context_uuid('boardagent.organization_id')
     and boardagent_context_board_allowed(document.board_id)
     and boardagent_document_secretary_for_board(document.board_id)
     and document.state='active';
  if source_board_id is null then
    return;
  end if;
  return query
    select membership.member_id,
           membership.entitlement_generation,
           member.state='active'
             and membership.state='active'
             and membership.active_from<=transaction_timestamp()
             and (membership.active_until is null
                  or membership.active_until>transaction_timestamp())
             and (
               document.created_by=membership.member_id
               or exists (
                 select 1 from document_access_grants as access_grant
                  where access_grant.document_id=document.id
                    and access_grant.organization_id=document.organization_id
                    and access_grant.board_id=document.board_id
                    and access_grant.active_from<=transaction_timestamp()
                    and (access_grant.active_until is null
                         or access_grant.active_until>transaction_timestamp())
                    and (access_grant.grantee_member_id=membership.member_id
                         or access_grant.grantee_seat_role=membership.seat_role)
                    and access_grant.permission in ('read','contribute','circulate')
               )
             )
             and not exists (
               select 1 from document_exclusions as exclusion
                where exclusion.document_id=document.id
                  and exclusion.organization_id=document.organization_id
                  and exclusion.board_id=document.board_id
                  and exclusion.member_id=membership.member_id
                  and exclusion.active_from<=transaction_timestamp()
                  and (exclusion.active_until is null
                       or exclusion.active_until>transaction_timestamp())
             ),
           exists (
             select 1 from circulation_recipients as prior_recipient
             join document_circulations as prior_circulation
               on prior_circulation.id=prior_recipient.circulation_id
              and prior_circulation.document_id=candidate_document_id
              and prior_circulation.document_version_id=candidate_version_id
              and prior_circulation.state='committed'
            where prior_recipient.member_id=membership.member_id
           )
      from documents as document
      join board_memberships as membership
        on membership.organization_id=document.organization_id
       and membership.board_id=document.board_id
      join members as member
        on member.organization_id=membership.organization_id
       and member.id=membership.member_id
     where document.id=candidate_document_id
       and document.organization_id=source_organization_id
       and document.board_id=source_board_id
       and membership.member_id=any(candidate_member_ids)
     order by membership.member_id
     for update of membership,member;
end
$$;
alter function boardagent_lock_document_recipients(uuid,uuid,uuid[])
  owner to boardagent_migrator;
revoke all on function boardagent_lock_document_recipients(uuid,uuid,uuid[]) from public;
grant execute on function boardagent_lock_document_recipients(uuid,uuid,uuid[])
  to boardagent_server;

create function boardagent_document_retention_manifest(candidate_document_id uuid)
returns table(
  version_id uuid,
  version_number integer,
  media_type text,
  document_schema text,
  byte_length integer,
  sha256 bytea
)
language sql
stable
security definer
set search_path=pg_catalog,public
as $$
  select version.id,version.version,version.media_type,version.document_schema,
         version.byte_length,version.sha256
    from documents as document
    join document_versions as version on version.document_id=document.id
   where document.id=candidate_document_id
     and document.organization_id=boardagent_context_uuid('boardagent.organization_id')
     and boardagent_context_board_allowed(document.board_id)
     and boardagent_document_admin_for_board(document.board_id)
   order by version.version
$$;
alter function boardagent_document_retention_manifest(uuid)
  owner to boardagent_migrator;
revoke all on function boardagent_document_retention_manifest(uuid) from public;
grant execute on function boardagent_document_retention_manifest(uuid)
  to boardagent_server;

create function boardagent_apply_document_terminal_transition(
  candidate_document_id uuid,
  expected_row_version bigint,
  candidate_state text,
  candidate_consent_record_id uuid,
  expected_version_id uuid,
  expected_document_sha256 bytea
)
returns bigint
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  changed_version bigint;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or candidate_state not in ('archived','soft_deleted')
     or not exists (
       select 1 from consent_records as consent
       join documents as document on document.id=candidate_document_id
       join document_versions as version on version.id=document.current_version_id
        where consent.id=candidate_consent_record_id
          and consent.organization_id=document.organization_id
          and consent.board_id=document.board_id
          and consent.actor_member_id=boardagent_context_uuid('boardagent.member_id')
          and consent.client_id=boardagent_context_uuid('boardagent.client_id')
          and consent.token_jti=boardagent_context_uuid('boardagent.token_jti')
          and consent.target_type='document'
          and consent.target_id=document.id
          and consent.action_code=case candidate_state
            when 'archived' then 'archive_document'
            else 'soft_delete_document'
          end
          and document.organization_id=boardagent_context_uuid('boardagent.organization_id')
          and boardagent_context_board_allowed(document.board_id)
          and boardagent_secretariat_for_board(document.board_id)
          and (candidate_state<>'soft_deleted'
               or boardagent_document_admin_for_board(document.board_id))
          and document.current_version_id=expected_version_id
          and version.sha256=expected_document_sha256
     ) then
    raise exception 'document terminal transition lacks exact confirmed authority'
      using errcode='42501';
  end if;
  update documents
     set state=candidate_state,
         hidden_at=case when candidate_state='soft_deleted'
                        then transaction_timestamp() else hidden_at end,
         row_version=row_version+1
   where id=candidate_document_id
     and row_version=expected_row_version
     and ((candidate_state='archived' and state='active')
          or (candidate_state='soft_deleted' and state in ('active','archived')))
   returning row_version into changed_version;
  if changed_version is null then
    raise exception 'document changed before terminal transition' using errcode='40001';
  end if;
  return changed_version;
end
$$;
alter function boardagent_apply_document_terminal_transition(uuid,bigint,text,uuid,uuid,bytea)
  owner to boardagent_migrator;
revoke all on function boardagent_apply_document_terminal_transition(uuid,bigint,text,uuid,uuid,bytea)
  from public;
grant execute on function boardagent_apply_document_terminal_transition(uuid,bigint,text,uuid,uuid,bytea)
  to boardagent_server;
