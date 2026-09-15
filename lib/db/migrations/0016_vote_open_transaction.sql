-- BoardAgent Phase 1 / group 16: exact vote-open authority and lock capabilities.

grant select on
  approval_rules,
  governance_profiles,
  rulesets,
  consent_records,
  action_stages,
  input_required_attempts,
  membership_versions,
  resolution_versions,
  vote_electorate,
  vote_exclusions
to boardagent_migrator;
grant update on
  approval_rules,
  governance_profiles,
  rulesets,
  membership_versions,
  resolution_versions,
  board_memberships,
  members
to boardagent_migrator;

do $migrator_vote_read$
declare
  source_table text;
begin
  foreach source_table in array array[
    'approval_rules', 'governance_profiles', 'rulesets', 'consent_records',
    'action_stages', 'input_required_attempts', 'membership_versions',
    'resolution_versions', 'vote_electorate', 'vote_exclusions'
  ]
  loop
    execute format(
      'create policy boardagent_migrator_vote_read on %I for select to boardagent_migrator using (true)',
      source_table
    );
  end loop;
end
$migrator_vote_read$;

do $migrator_vote_lock$
declare
  source_table text;
begin
  foreach source_table in array array[
    'approval_rules', 'governance_profiles', 'rulesets', 'membership_versions',
    'resolution_versions', 'board_memberships', 'members'
  ]
  loop
    execute format(
      'create policy boardagent_migrator_vote_lock on %I for update to boardagent_migrator using (true) with check (true)',
      source_table
    );
  end loop;
end
$migrator_vote_lock$;

create function boardagent_vote_actor_ready(candidate_board uuid)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select boardagent_context_board_allowed(candidate_board)
     and exists (
       select 1
         from members as actor
         join board_memberships as membership
           on membership.organization_id = actor.organization_id
          and membership.member_id = actor.id
          and membership.board_id = candidate_board
         join access_token_records as token
           on token.organization_id = actor.organization_id
          and token.member_id = actor.id
          and token.client_id = boardagent_context_uuid('boardagent.client_id')
          and token.jti = boardagent_context_uuid('boardagent.token_jti')
         join oauth_clients as client on client.id = token.client_id
         join system_instance as instance
           on instance.organization_id = actor.organization_id
          and instance.canonical_resource_uri = token.resource_uri
        where actor.organization_id = boardagent_context_uuid('boardagent.organization_id')
          and actor.id = boardagent_context_uuid('boardagent.member_id')
          and actor.state = 'active'
          and membership.state = 'active'
          and membership.active_from <= transaction_timestamp()
          and (membership.active_until is null or membership.active_until > transaction_timestamp())
          and client.organization_id = actor.organization_id
          and client.state = 'active'
          and token.revoked_at is null
          and token.expires_at > transaction_timestamp()
          and 'secretariat:admin' = any(token.scope_set)
          and (
            membership.is_secretary
            or exists (
              select 1
                from organization_role_assignments as assignment
               where assignment.organization_id = actor.organization_id
                 and assignment.member_id = actor.id
                 and assignment.role in ('admin', 'secretariat')
                 and assignment.active_from <= transaction_timestamp()
                 and (
                   assignment.active_until is null
                   or assignment.active_until > transaction_timestamp()
                 )
            )
          )
          and exists (
            select 1
              from onboarding_attestations as attestation
             where attestation.organization_id = actor.organization_id
               and attestation.member_id = actor.id
               and attestation.board_id = candidate_board
               and attestation.terms_version_id = (
                 select terms.id
                   from onboarding_terms_versions as terms
                  where terms.organization_id = actor.organization_id
                    and terms.seat_role = membership.seat_role
                    and terms.effective_at <= transaction_timestamp()
                  order by terms.effective_at desc, terms.version desc, terms.id desc
                  limit 1
               )
               and attestation.support_version_id = (
                 select support.id
                   from secretary_support_versions as support
                  where support.organization_id = actor.organization_id
                    and (support.board_id = candidate_board or support.board_id is null)
                    and support.effective_at <= transaction_timestamp()
                  order by (support.board_id = candidate_board) desc,
                           support.effective_at desc,
                           support.version desc,
                           support.id desc
                  limit 1
               )
          )
     )
$$;
alter function boardagent_vote_actor_ready(uuid) owner to boardagent_migrator;
revoke all on function boardagent_vote_actor_ready(uuid) from public;
grant execute on function boardagent_vote_actor_ready(uuid) to boardagent_server;

create function boardagent_lock_vote_for_open(
  candidate_vote uuid,
  candidate_resolution uuid,
  candidate_consent uuid,
  candidate_package_sha256 bytea
)
returns table(
  organization_id uuid,
  board_id uuid,
  vote_state text,
  vote_row_version bigint,
  approval_rule_id uuid,
  approval_rule_sha256 bytea,
  governance_profile_id uuid,
  governance_profile_version integer,
  governance_profile_sha256 bytea,
  ruleset_id uuid,
  ruleset_version integer,
  ruleset_sha256 bytea,
  close_mode text,
  resolution_version integer,
  resolution_sha256 bytea,
  actor_ready boolean,
  binding_valid boolean,
  consent_valid boolean
)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request' then
    raise exception 'vote open requires a managed request transaction'
      using errcode = '25000';
  end if;
  if candidate_package_sha256 is null or octet_length(candidate_package_sha256) <> 32 then
    raise exception 'vote package hash is invalid' using errcode = '22023';
  end if;
  return query
    select vote.organization_id,
           vote.board_id,
           vote.state,
           vote.row_version,
           rule.id,
           rule.canonical_sha256,
           profile.id,
           profile.version,
           profile.canonical_sha256,
           ruleset.id,
           ruleset.version,
           ruleset.canonical_sha256,
           vote.close_mode,
           resolution.version,
           resolution.canonical_sha256,
           boardagent_vote_actor_ready(vote.board_id),
           (
             (
               (vote.state = 'draft' and vote.current_decision_package_id is null)
               or (
                 vote.state = 'open'
                 and exists (
                   select 1
                     from decision_packages as package
                    where package.id = vote.current_decision_package_id
                      and package.vote_id = vote.id
                      and package.package_sha256 = candidate_package_sha256
                 )
               )
             )
             and board.state = 'active'
             and board.current_governance_profile_id = profile.id
             and board.current_ruleset_id = ruleset.id
             and profile.state = 'active'
             and ruleset.state = 'active'
             and ruleset.profile_id = profile.id
             and rule.organization_id = vote.organization_id
             and rule.board_id = vote.board_id
             and rule.close_mode = vote.close_mode
             and profile.organization_id = vote.organization_id
             and profile.board_id = vote.board_id
             and ruleset.organization_id = vote.organization_id
             and ruleset.board_id = vote.board_id
             and resolution.organization_id = vote.organization_id
             and resolution.board_id = vote.board_id
           ),
           exists (
             select 1
               from consent_records as consent
               join action_stages as stage on stage.id = consent.stage_id
               join input_required_attempts as attempt
                 on attempt.id = consent.input_required_attempt_id
              where consent.id = candidate_consent
                and consent.organization_id = vote.organization_id
                and consent.board_id = vote.board_id
                and consent.actor_member_id = boardagent_context_uuid('boardagent.member_id')
                and consent.client_id = boardagent_context_uuid('boardagent.client_id')
                and consent.token_jti = boardagent_context_uuid('boardagent.token_jti')
                and consent.action_code = 'create_vote'
                and consent.target_type = 'vote'
                and consent.target_id = vote.id
                and consent.payload_sha256 = candidate_package_sha256
                and consent.package_sha256 = candidate_package_sha256
                and stage.organization_id = consent.organization_id
                and stage.board_id = consent.board_id
                and stage.actor_member_id = consent.actor_member_id
                and stage.client_id = consent.client_id
                and stage.token_jti = consent.token_jti
                and stage.action_code = consent.action_code
                and stage.target_type = consent.target_type
                and stage.target_id = consent.target_id
                and stage.payload_sha256 = consent.payload_sha256
                and stage.package_sha256 = consent.package_sha256
                and stage.state = 'confirmed'
                and stage.confirmed_at is not null
                and attempt.organization_id = consent.organization_id
                and attempt.stage_id = stage.id
                and attempt.original_method = 'tools/call'
                and attempt.original_name = 'create_vote'
                and attempt.response_action = 'accept'
                and attempt.state = 'confirmed'
           )
      from votes as vote
      join boards as board on board.id = vote.board_id
      join approval_rules as rule on rule.id = vote.approval_rule_id
      join governance_profiles as profile on profile.id = vote.governance_profile_id
      join rulesets as ruleset on ruleset.id = vote.ruleset_id
      join resolution_versions as resolution
        on resolution.vote_id = vote.id and resolution.id = candidate_resolution
     where vote.id = candidate_vote
       and vote.organization_id = boardagent_context_uuid('boardagent.organization_id')
       and boardagent_context_board_allowed(vote.board_id)
     for update of vote
     for share of board, rule, profile, ruleset, resolution;
end
$$;
alter function boardagent_lock_vote_for_open(uuid, uuid, uuid, bytea)
  owner to boardagent_migrator;
revoke all on function boardagent_lock_vote_for_open(uuid, uuid, uuid, bytea) from public;
grant execute on function boardagent_lock_vote_for_open(uuid, uuid, uuid, bytea)
  to boardagent_server;

create function boardagent_lock_vote_electorate(candidate_vote uuid)
returns table(
  member_id uuid,
  membership_id uuid,
  membership_version_id uuid,
  membership_version integer,
  voting_weight bigint,
  authority_snapshot jsonb,
  authority_snapshot_sha256 bytea
)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request' then
    raise exception 'vote electorate freeze requires a managed request transaction'
      using errcode = '25000';
  end if;
  return query
    select membership.member_id,
           membership.id,
           version.id,
           version.version,
           membership.voting_weight,
           version.authority_snapshot,
           version.snapshot_sha256
      from votes as vote
      join board_memberships as membership
        on membership.organization_id = vote.organization_id
       and membership.board_id = vote.board_id
      join lateral (
        select candidate.id,
               candidate.version,
               candidate.seat_role,
               candidate.voting_weight,
               candidate.authority_snapshot,
               candidate.snapshot_sha256
          from membership_versions as candidate
         where candidate.membership_id = membership.id
         order by candidate.version desc, candidate.id desc
         limit 1
      ) as version on true
     where vote.id = candidate_vote
       and vote.organization_id = boardagent_context_uuid('boardagent.organization_id')
       and vote.state = 'draft'
       and boardagent_vote_actor_ready(vote.board_id)
       and membership.state = 'active'
       and membership.active_from <= transaction_timestamp()
       and (membership.active_until is null or membership.active_until > transaction_timestamp())
       and membership.seat_role = 'voting_member'
       and version.seat_role = membership.seat_role
       and version.voting_weight = membership.voting_weight
       and not exists (
         select 1 from vote_exclusions as exclusion
          where exclusion.vote_id = vote.id
            and exclusion.member_id = membership.member_id
            and exclusion.state = 'excluded'
       )
     order by membership.member_id
     for update of membership
     for share of version;
end
$$;
alter function boardagent_lock_vote_electorate(uuid) owner to boardagent_migrator;
revoke all on function boardagent_lock_vote_electorate(uuid) from public;
grant execute on function boardagent_lock_vote_electorate(uuid) to boardagent_server;

create function boardagent_lock_vote_recipients(candidate_vote uuid)
returns table(member_id uuid, seat_role text, entitlement_generation bigint)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request' then
    raise exception 'vote recipient freeze requires a managed request transaction'
      using errcode = '25000';
  end if;
  return query
    select membership.member_id,
           membership.seat_role,
           membership.entitlement_generation
      from votes as vote
      join board_memberships as membership
        on membership.organization_id = vote.organization_id
       and membership.board_id = vote.board_id
      join members as recipient
        on recipient.organization_id = membership.organization_id
       and recipient.id = membership.member_id
     where vote.id = candidate_vote
       and vote.organization_id = boardagent_context_uuid('boardagent.organization_id')
       and vote.state = 'draft'
       and boardagent_vote_actor_ready(vote.board_id)
       and recipient.state = 'active'
       and membership.state = 'active'
       and membership.active_from <= transaction_timestamp()
       and (membership.active_until is null or membership.active_until > transaction_timestamp())
       and exists (
         select 1
           from onboarding_attestations as attestation
          where attestation.organization_id = membership.organization_id
            and attestation.member_id = membership.member_id
            and attestation.board_id = membership.board_id
            and attestation.terms_version_id = (
              select terms.id
                from onboarding_terms_versions as terms
               where terms.organization_id = membership.organization_id
                 and terms.seat_role = membership.seat_role
                 and terms.effective_at <= transaction_timestamp()
               order by terms.effective_at desc, terms.version desc, terms.id desc
               limit 1
            )
            and attestation.support_version_id = (
              select support.id
                from secretary_support_versions as support
               where support.organization_id = membership.organization_id
                 and (support.board_id = membership.board_id or support.board_id is null)
                 and support.effective_at <= transaction_timestamp()
               order by (support.board_id = membership.board_id) desc,
                        support.effective_at desc,
                        support.version desc,
                        support.id desc
               limit 1
            )
       )
     order by membership.member_id
     for update of membership
     for share of recipient;
end
$$;
alter function boardagent_lock_vote_recipients(uuid) owner to boardagent_migrator;
revoke all on function boardagent_lock_vote_recipients(uuid) from public;
grant execute on function boardagent_lock_vote_recipients(uuid) to boardagent_server;

-- This child table has no organization/board columns, so its RLS follows the parent.
create policy boardagent_server_decision_package_components_select
  on decision_package_components for select to boardagent_server
  using (
    exists (
      select 1 from decision_packages as package
       where package.id = decision_package_id
         and package.organization_id = boardagent_context_uuid('boardagent.organization_id')
         and boardagent_context_board_allowed(package.board_id)
    )
  );
create policy boardagent_server_decision_package_components_insert
  on decision_package_components for insert to boardagent_server
  with check (
    exists (
      select 1 from decision_packages as package
       where package.id = decision_package_id
         and package.organization_id = boardagent_context_uuid('boardagent.organization_id')
         and boardagent_context_board_allowed(package.board_id)
         and boardagent_vote_actor_ready(package.board_id)
    )
  );

create policy boardagent_server_question_links_insert on question_decision_links
  for insert to boardagent_server
  with check (
    question_decision_links.organization_id = boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(question_decision_links.board_id)
    and question_decision_links.selected_by = boardagent_context_uuid('boardagent.member_id')
    and boardagent_vote_actor_ready(question_decision_links.board_id)
    and exists (
      select 1
        from decision_packages as package
        join votes as vote on vote.id = package.vote_id
        join consent_records as consent
          on consent.id = question_decision_links.consent_record_id
       where package.id = question_decision_links.decision_package_id
         and package.organization_id = question_decision_links.organization_id
         and package.board_id = question_decision_links.board_id
         and package.version = question_decision_links.decision_package_version
         and package.package_sha256 = question_decision_links.decision_package_sha256
         and consent.organization_id = question_decision_links.organization_id
         and consent.board_id = question_decision_links.board_id
         and consent.actor_member_id = question_decision_links.selected_by
         and consent.client_id = boardagent_context_uuid('boardagent.client_id')
         and consent.token_jti = boardagent_context_uuid('boardagent.token_jti')
         and consent.action_code in ('create_vote', 'replace_open_vote')
         and consent.target_type = 'vote'
         and consent.target_id = vote.id
         and consent.package_sha256 = package.package_sha256
    )
  );
