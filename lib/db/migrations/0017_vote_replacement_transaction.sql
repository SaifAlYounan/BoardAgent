-- BoardAgent Phase 1 / group 17: atomic open-vote replacement and no-carry locks.

alter table ballot_dispositions
  alter constraint ballot_dispositions_audit_event_fk
  deferrable initially deferred;

grant select on decision_packages to boardagent_migrator;
grant update on decision_packages to boardagent_migrator;
create policy boardagent_migrator_vote_replacement_lock on decision_packages
  for update to boardagent_migrator using (true) with check (true);

create policy boardagent_server_ballot_dispositions_select
  on ballot_dispositions for select to boardagent_server
  using (
    exists (
      select 1
        from ballots as ballot
       where ballot.id = prior_ballot_id
         and ballot.organization_id = boardagent_context_uuid('boardagent.organization_id')
         and boardagent_context_board_allowed(ballot.board_id)
    )
  );
create policy boardagent_server_ballot_dispositions_insert
  on ballot_dispositions for insert to boardagent_server
  with check (
    effect = 'invalidated_by_vote_replacement'
    and superseding_ballot_id is null
    and replacement_vote_id is not null
    and exists (
      select 1
        from ballots as ballot
        join votes as old_vote on old_vote.id = ballot.vote_id
        join votes as new_vote on new_vote.id = replacement_vote_id
       where ballot.id = prior_ballot_id
         and ballot.organization_id = boardagent_context_uuid('boardagent.organization_id')
         and boardagent_context_board_allowed(ballot.board_id)
         and old_vote.board_id = ballot.board_id
         and new_vote.organization_id = ballot.organization_id
         and new_vote.board_id = ballot.board_id
         and boardagent_vote_actor_ready(ballot.board_id)
    )
  );

create function boardagent_lock_vote_for_replacement(
  candidate_old_vote uuid,
  candidate_consent uuid,
  candidate_payload_sha256 bytea,
  candidate_new_package_sha256 bytea,
  candidate_approval_rule uuid,
  candidate_governance_profile uuid,
  candidate_ruleset uuid,
  candidate_close_mode text
)
returns table(
  organization_id uuid,
  board_id uuid,
  vote_state text,
  vote_row_version bigint,
  old_package_payload bytea,
  old_package_sha256 bytea,
  approval_rule_sha256 bytea,
  governance_profile_version integer,
  governance_profile_sha256 bytea,
  ruleset_version integer,
  ruleset_sha256 bytea,
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
    raise exception 'vote replacement requires a managed request transaction'
      using errcode = '25000';
  end if;
  if candidate_payload_sha256 is null
     or octet_length(candidate_payload_sha256) <> 32
     or candidate_new_package_sha256 is null
     or octet_length(candidate_new_package_sha256) <> 32 then
    raise exception 'replacement confirmation hash is invalid' using errcode = '22023';
  end if;
  return query
    select vote.organization_id,
           vote.board_id,
           vote.state,
           vote.row_version,
           package.canonical_payload,
           package.package_sha256,
           rule.canonical_sha256,
           profile.version,
           profile.canonical_sha256,
           ruleset.version,
           ruleset.canonical_sha256,
           boardagent_vote_actor_ready(vote.board_id),
           (
             board.state = 'active'
             and board.current_governance_profile_id = profile.id
             and board.current_ruleset_id = ruleset.id
             and profile.state = 'active'
             and profile.organization_id = vote.organization_id
             and profile.board_id = vote.board_id
             and ruleset.state = 'active'
             and ruleset.organization_id = vote.organization_id
             and ruleset.board_id = vote.board_id
             and ruleset.profile_id = profile.id
             and rule.organization_id = vote.organization_id
             and rule.board_id = vote.board_id
             and rule.close_mode = candidate_close_mode
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
                and consent.action_code = 'replace_open_vote'
                and consent.target_type = 'vote'
                and consent.target_id = vote.id
                and consent.payload_sha256 = candidate_payload_sha256
                and consent.package_sha256 = candidate_new_package_sha256
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
                and attempt.original_name = 'replace_open_vote'
                and attempt.response_action = 'accept'
                and attempt.state = 'confirmed'
           )
      from votes as vote
      join decision_packages as package
        on package.id = vote.current_decision_package_id
       and package.vote_id = vote.id
      join boards as board on board.id = vote.board_id
      join approval_rules as rule on rule.id = candidate_approval_rule
      join governance_profiles as profile on profile.id = candidate_governance_profile
      join rulesets as ruleset on ruleset.id = candidate_ruleset
     where vote.id = candidate_old_vote
       and vote.organization_id = boardagent_context_uuid('boardagent.organization_id')
       and boardagent_context_board_allowed(vote.board_id)
     for update of vote
     for share of package, board, rule, profile, ruleset;
end
$$;
alter function boardagent_lock_vote_for_replacement(uuid, uuid, bytea, bytea, uuid, uuid, uuid, text)
  owner to boardagent_migrator;
revoke all on function boardagent_lock_vote_for_replacement(uuid, uuid, bytea, bytea, uuid, uuid, uuid, text)
  from public;
grant execute on function boardagent_lock_vote_for_replacement(uuid, uuid, bytea, bytea, uuid, uuid, uuid, text)
  to boardagent_server;

create function boardagent_lock_replacement_electorate(candidate_old_vote uuid)
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
    raise exception 'vote replacement electorate requires a managed request transaction'
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
     where vote.id = candidate_old_vote
       and vote.organization_id = boardagent_context_uuid('boardagent.organization_id')
       and vote.state in ('open', 'source_update_pending')
       and boardagent_vote_actor_ready(vote.board_id)
       and membership.state = 'active'
       and membership.active_from <= transaction_timestamp()
       and (membership.active_until is null or membership.active_until > transaction_timestamp())
       and membership.seat_role = 'voting_member'
       and version.seat_role = membership.seat_role
       and version.voting_weight = membership.voting_weight
       and not exists (
         select 1
           from vote_exclusions as exclusion
          where exclusion.vote_id = vote.id
            and exclusion.member_id = membership.member_id
            and exclusion.state = 'excluded'
       )
     order by membership.member_id
     for update of membership
     for share of version;
end
$$;
alter function boardagent_lock_replacement_electorate(uuid) owner to boardagent_migrator;
revoke all on function boardagent_lock_replacement_electorate(uuid) from public;
grant execute on function boardagent_lock_replacement_electorate(uuid) to boardagent_server;

create function boardagent_lock_replacement_recipients(candidate_old_vote uuid)
returns table(member_id uuid, seat_role text, entitlement_generation bigint)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request' then
    raise exception 'vote replacement recipients require a managed request transaction'
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
     where vote.id = candidate_old_vote
       and vote.organization_id = boardagent_context_uuid('boardagent.organization_id')
       and vote.state in ('open', 'source_update_pending')
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
alter function boardagent_lock_replacement_recipients(uuid) owner to boardagent_migrator;
revoke all on function boardagent_lock_replacement_recipients(uuid) from public;
grant execute on function boardagent_lock_replacement_recipients(uuid) to boardagent_server;
