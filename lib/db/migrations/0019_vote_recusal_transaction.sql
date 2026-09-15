-- BoardAgent Phase 1 / group 19: append-only live vote recusal and act invalidation.

drop index vote_exclusions_one_live_uq;
create trigger boardagent_vote_exclusions_immutable
  before update or delete on vote_exclusions
  for each row execute function boardagent_reject_evidence_mutation();
revoke update, delete on vote_exclusions from boardagent_server, boardagent_worker;

create function boardagent_vote_member_excluded(candidate_vote uuid, candidate_member uuid)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select coalesce((
    select exclusion.state = 'excluded'
      from vote_exclusions as exclusion
     where exclusion.vote_id = candidate_vote
       and exclusion.member_id = candidate_member
     order by exclusion.version desc, exclusion.id desc
     limit 1
  ), false)
$$;
alter function boardagent_vote_member_excluded(uuid, uuid) owner to boardagent_migrator;
revoke all on function boardagent_vote_member_excluded(uuid, uuid) from public;

create or replace function boardagent_lock_replacement_electorate(candidate_old_vote uuid)
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
       and not boardagent_vote_member_excluded(vote.id, membership.member_id)
     order by membership.member_id
     for update of membership
     for share of version;
end
$$;
alter function boardagent_lock_replacement_electorate(uuid) owner to boardagent_migrator;
revoke all on function boardagent_lock_replacement_electorate(uuid) from public;
grant execute on function boardagent_lock_replacement_electorate(uuid) to boardagent_server;

create policy boardagent_server_ballot_dispositions_recusal_insert
  on ballot_dispositions for insert to boardagent_server
  with check (
    effect = 'invalidated_by_recusal'
    and superseding_ballot_id is null
    and replacement_vote_id is null
    and exists (
      select 1
        from ballots as ballot
       where ballot.id = prior_ballot_id
         and ballot.organization_id = boardagent_context_uuid('boardagent.organization_id')
         and boardagent_context_board_allowed(ballot.board_id)
         and boardagent_vote_actor_ready(ballot.board_id)
    )
  );

create function boardagent_lock_vote_for_recusal(
  candidate_vote uuid,
  candidate_member uuid,
  candidate_consent uuid,
  candidate_payload_sha256 bytea
)
returns table(
  organization_id uuid,
  board_id uuid,
  vote_state text,
  vote_row_version bigint,
  decision_package_id uuid,
  package_sha256 bytea,
  electorate_weight bigint,
  current_exclusion_id uuid,
  current_exclusion_version integer,
  current_exclusion_state text,
  actor_ready boolean,
  consent_valid boolean
)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request' then
    raise exception 'vote recusal requires a managed request transaction'
      using errcode = '25000';
  end if;
  if candidate_payload_sha256 is null or octet_length(candidate_payload_sha256) <> 32 then
    raise exception 'vote recusal payload hash is invalid' using errcode = '22023';
  end if;
  return query
    select vote.organization_id,
           vote.board_id,
           vote.state,
           vote.row_version,
           package.id,
           package.package_sha256,
           electorate.voting_weight,
           current_exclusion.id,
           current_exclusion.version,
           current_exclusion.state,
           boardagent_vote_actor_ready(vote.board_id),
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
                and consent.action_code = 'manage_recusal'
                and consent.target_type = 'vote'
                and consent.target_id = vote.id
                and consent.payload_sha256 = candidate_payload_sha256
                and consent.package_sha256 = package.package_sha256
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
                and attempt.original_name = 'manage_recusal'
                and attempt.response_action = 'accept'
                and attempt.state = 'confirmed'
           )
      from votes as vote
      join decision_packages as package
        on package.id = vote.current_decision_package_id
       and package.vote_id = vote.id
      join vote_electorate as electorate
        on electorate.vote_id = vote.id
       and electorate.member_id = candidate_member
      join members as target_member
        on target_member.organization_id = vote.organization_id
       and target_member.id = electorate.member_id
      join board_memberships as membership
        on membership.organization_id = vote.organization_id
       and membership.board_id = vote.board_id
       and membership.member_id = electorate.member_id
      left join lateral (
        select exclusion.id, exclusion.version, exclusion.state
          from vote_exclusions as exclusion
         where exclusion.vote_id = vote.id
           and exclusion.member_id = electorate.member_id
         order by exclusion.version desc, exclusion.id desc
         limit 1
      ) as current_exclusion on true
     where vote.id = candidate_vote
       and vote.organization_id = boardagent_context_uuid('boardagent.organization_id')
       and boardagent_context_board_allowed(vote.board_id)
       and target_member.state = 'active'
       and membership.state = 'active'
       and membership.active_from <= transaction_timestamp()
       and (membership.active_until is null or membership.active_until > transaction_timestamp())
     for update of vote, target_member, membership
     for share of package;
end
$$;
alter function boardagent_lock_vote_for_recusal(uuid, uuid, uuid, bytea)
  owner to boardagent_migrator;
revoke all on function boardagent_lock_vote_for_recusal(uuid, uuid, uuid, bytea) from public;
grant execute on function boardagent_lock_vote_for_recusal(uuid, uuid, uuid, bytea)
  to boardagent_server;
