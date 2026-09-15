-- BoardAgent Phase 1 / transaction 15: recoverable vote close, exact outcome,
-- clock-health evidence, and signed certificate state.

alter table board_memberships
  add column is_chair boolean not null default false,
  add constraint board_memberships_chair_voter_check
    check (not is_chair or seat_role = 'voting_member');
create unique index board_memberships_one_active_chair_uq
  on board_memberships(board_id)
  where is_chair and state = 'active' and active_until is null;

alter table membership_versions
  add column is_chair boolean not null default false,
  add constraint membership_versions_chair_voter_check
    check (not is_chair or seat_role = 'voting_member');

alter table vote_electorate
  add column is_chair boolean not null default false,
  add constraint vote_electorate_chair_voter_check
    check (not is_chair or seat_role = 'voting_member');
create unique index vote_electorate_one_chair_uq
  on vote_electorate(vote_id)
  where is_chair;

create table clock_health_samples (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null references organizations(id) on delete restrict,
  source text not null check (source ~ '^[a-z][a-z0-9_.-]{1,127}$'),
  measured_at timestamptz(6) not null,
  drift_microseconds bigint not null,
  valid_until timestamptz(6) not null,
  recorded_at timestamptz(6) not null default transaction_timestamp(),
  healthy boolean generated always as (
    drift_microseconds between -2000000 and 2000000
  ) stored,
  check (valid_until > measured_at),
  check (measured_at <= recorded_at + interval '1 minute')
);
create index clock_health_samples_current_idx
  on clock_health_samples(organization_id, measured_at desc, id desc);

do $vote_close_upgrade$
begin
  if exists (select 1 from vote_outcomes) or exists (select 1 from vote_certificates) then
    raise exception
      'migration 0023 cannot reconstruct pre-release outcome/certificate rows; verify and migrate them explicitly';
  end if;
end
$vote_close_upgrade$;

alter table vote_outcomes
  add column close_mode text not null
    check (close_mode in ('automatic', 'secretariat_confirmed')),
  add column close_actor_member_id uuid,
  add column close_consent_record_id uuid references consent_records(id) on delete restrict,
  add column certificate_id uuid not null unique check (boardagent_is_uuid_v7(certificate_id)),
  add column certificate_public_id bytea not null unique
    check (octet_length(certificate_public_id) = 32),
  add column canonical_certificate_payload bytea not null
    check (octet_length(canonical_certificate_payload) between 2 and 10485760),
  add column certificate_payload_sha256 bytea not null unique
    check (boardagent_hash_is_sha256(certificate_payload_sha256)),
  add column signing_key_id uuid not null references crypto_key_registry(id) on delete restrict,
  add column clock_sample_id uuid not null references clock_health_samples(id) on delete restrict,
  add column closing_audit_event_id uuid not null unique
    references audit_events(id) on delete restrict,
  add column close_request_sha256 bytea not null
    check (boardagent_hash_is_sha256(close_request_sha256)),
  add constraint vote_outcomes_close_actor_fk
    foreign key (organization_id, close_actor_member_id)
    references members(organization_id, id) on delete restrict,
  add constraint vote_outcomes_close_mode_evidence_check
    check (
      (close_mode = 'secretariat_confirmed'
        and close_actor_member_id is not null
        and close_consent_record_id is not null)
      or
      (close_mode = 'automatic'
        and close_actor_member_id is null
        and close_consent_record_id is null)
    );

alter table vote_certificates
  add column certificate_issued_audit_event_id uuid not null unique
    references audit_events(id) on delete restrict,
  add column vote_closed_audit_event_id uuid not null unique
    references audit_events(id) on delete restrict,
  add constraint vote_certificates_distinct_close_events_check
    check (certificate_issued_audit_event_id <> vote_closed_audit_event_id);

-- Runtime roles created before this migration do not inherit privileges or RLS
-- policies for a new table.
alter table clock_health_samples enable row level security;
alter table clock_health_samples force row level security;
grant select on clock_health_samples to boardagent_backup;
create policy boardagent_backup_read on clock_health_samples
  for select to boardagent_backup using (true);
grant select on clock_health_samples to boardagent_server;
create policy boardagent_server_clock_health on clock_health_samples
  for select to boardagent_server using (
    organization_id = boardagent_context_uuid('boardagent.organization_id')
  );
grant select, insert on clock_health_samples to boardagent_migrator;
create policy boardagent_migrator_clock_health on clock_health_samples
  for all to boardagent_migrator using (true) with check (true);

create trigger boardagent_immutable
  before update or delete on clock_health_samples
  for each row execute function boardagent_reject_evidence_mutation();
revoke update, delete on clock_health_samples from boardagent_server, boardagent_worker;

grant select on
  access_token_records,
  action_stages,
  approval_rules,
  ballot_dispositions,
  ballots,
  board_memberships,
  boards,
  consent_records,
  crypto_key_registry,
  decision_packages,
  input_required_attempts,
  matter_evaluations,
  members,
  membership_versions,
  proxy_grants,
  proxy_revocations,
  resolution_versions,
  rule_overrides,
  ruleset_rules,
  rulesets,
  system_instance,
  vote_certificates,
  vote_electorate,
  vote_exclusions,
  vote_outcomes,
  vote_source_update_causes,
  vote_source_update_dispositions,
  votes
to boardagent_migrator;
grant update on votes, board_memberships, membership_versions, crypto_key_registry
  to boardagent_migrator;
grant insert on vote_outcomes, vote_certificates to boardagent_migrator;
revoke insert on vote_outcomes, vote_certificates from boardagent_server, boardagent_worker;

do $migrator_vote_close_read$
declare
  source_table text;
begin
  foreach source_table in array array[
    'access_token_records', 'action_stages', 'approval_rules', 'ballot_dispositions',
    'ballots', 'board_memberships', 'boards', 'consent_records', 'crypto_key_registry',
    'decision_packages', 'input_required_attempts', 'matter_evaluations', 'members',
    'membership_versions', 'proxy_grants', 'proxy_revocations', 'resolution_versions',
    'rule_overrides', 'ruleset_rules', 'rulesets', 'system_instance',
    'vote_certificates', 'vote_electorate', 'vote_exclusions', 'vote_outcomes',
    'vote_source_update_causes', 'vote_source_update_dispositions', 'votes'
  ]
  loop
    execute format(
      'create policy boardagent_migrator_vote_close_read on %I for select to boardagent_migrator using (true)',
      source_table
    );
  end loop;
end
$migrator_vote_close_read$;

create policy boardagent_migrator_vote_close_update on votes
  for update to boardagent_migrator using (true) with check (true);
create policy boardagent_migrator_vote_close_lock on board_memberships
  for update to boardagent_migrator using (true) with check (true);
create policy boardagent_migrator_vote_close_lock on membership_versions
  for update to boardagent_migrator using (true) with check (true);
create policy boardagent_migrator_vote_close_lock on crypto_key_registry
  for update to boardagent_migrator using (true) with check (true);
create policy boardagent_migrator_vote_close_insert on vote_outcomes
  for insert to boardagent_migrator with check (true);
create policy boardagent_migrator_vote_close_insert on vote_certificates
  for insert to boardagent_migrator with check (true);

create function boardagent_record_clock_health(
  candidate_id uuid,
  candidate_organization uuid,
  candidate_source text,
  candidate_measured_at timestamptz,
  candidate_drift_microseconds bigint,
  candidate_valid_until timestamptz
)
returns table(
  sample_id uuid,
  healthy boolean,
  measured_at text,
  drift_microseconds bigint,
  valid_until text
)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'worker' then
    raise exception 'clock health requires a managed worker transaction'
      using errcode = '25000';
  end if;
  if candidate_source is null or candidate_source !~ '^[a-z][a-z0-9_.-]{1,127}$' then
    raise exception 'clock health source is invalid' using errcode = '22023';
  end if;
  insert into clock_health_samples(
    id, organization_id, source, measured_at, drift_microseconds, valid_until
  ) values (
    candidate_id, candidate_organization, candidate_source, candidate_measured_at,
    candidate_drift_microseconds, candidate_valid_until
  );
  return query
    select sample.id,
           sample.healthy,
           to_char(sample.measured_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
           sample.drift_microseconds,
           to_char(sample.valid_until at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
      from clock_health_samples as sample
     where sample.id = candidate_id;
end
$$;
alter function boardagent_record_clock_health(uuid, uuid, text, timestamptz, bigint, timestamptz)
  owner to boardagent_migrator;
revoke all on function boardagent_record_clock_health(uuid, uuid, text, timestamptz, bigint, timestamptz)
  from public;
grant execute on function boardagent_record_clock_health(uuid, uuid, text, timestamptz, bigint, timestamptz)
  to boardagent_worker;

-- Carry the constitutional chair bit into every newly frozen electorate. Existing
-- return signatures must be replaced explicitly because PostgreSQL will not alter a
-- table function's result row type in place.
drop function boardagent_lock_vote_electorate(uuid);
create function boardagent_lock_vote_electorate(candidate_vote uuid)
returns table(
  member_id uuid,
  membership_id uuid,
  membership_version_id uuid,
  membership_version integer,
  is_chair boolean,
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
           membership.is_chair,
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
               candidate.is_chair,
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
       and version.is_chair = membership.is_chair
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

drop function boardagent_lock_replacement_electorate(uuid);
create function boardagent_lock_replacement_electorate(candidate_old_vote uuid)
returns table(
  member_id uuid,
  membership_id uuid,
  membership_version_id uuid,
  membership_version integer,
  is_chair boolean,
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
           membership.is_chair,
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
               candidate.is_chair,
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
       and version.is_chair = membership.is_chair
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

create function boardagent_lock_vote_for_close(
  candidate_vote uuid,
  candidate_consent uuid,
  candidate_consent_sha256 bytea,
  candidate_signing_key uuid
)
returns table(
  organization_id uuid,
  board_id uuid,
  vote_id uuid,
  vote_state text,
  vote_row_version bigint,
  vote_title text,
  close_mode text,
  deadline_at text,
  resolution_version_id uuid,
  resolution_version integer,
  resolution_text text,
  resolution_sha256 bytea,
  decision_package_id uuid,
  decision_package_version integer,
  decision_package_sha256 bytea,
  submission_manifest_sha256 bytea,
  document_manifest_sha256 bytea,
  question_cutoff_sha256 bytea,
  electorate_sha256 bytea,
  governance_profile_id uuid,
  governance_profile_sha256 bytea,
  ruleset_id uuid,
  ruleset_sha256 bytea,
  matter_evaluation_id uuid,
  matter_evaluation_result_sha256 bytea,
  selected_ruleset_rule_id uuid,
  selected_ruleset_rule_sha256 bytea,
  rule_override_id uuid,
  rule_override_sha256 bytea,
  approval_rule_id uuid,
  approval_rule_sha256 bytea,
  threshold_numerator bigint,
  threshold_denominator bigint,
  quorum_numerator bigint,
  quorum_denominator bigint,
  approval_denominator text,
  abstentions_count_for_quorum boolean,
  tie_behavior text,
  proxy_policy text,
  instance_id uuid,
  signing_key_id uuid,
  signing_kid text,
  signing_public_jwk jsonb,
  signing_locator text,
  clock_sample_id uuid,
  clock_measured_at text,
  clock_drift_microseconds bigint,
  clock_valid_until text,
  close_consent_record_sha256 bytea,
  actor_ready boolean,
  package_binding_valid boolean,
  source_ready boolean,
  qna_ready boolean,
  clock_healthy boolean,
  key_valid boolean,
  consent_valid boolean
)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
declare
  transaction_scope text;
begin
  transaction_scope := current_setting('boardagent.transaction_scope', true);
  if transaction_scope is distinct from 'request'
     and transaction_scope is distinct from 'worker' then
    raise exception 'vote close requires a managed request transaction'
      using errcode = '25000';
  end if;
  if candidate_consent_sha256 is null or octet_length(candidate_consent_sha256) <> 32 then
    raise exception 'vote close consent hash is invalid' using errcode = '22023';
  end if;
  return query
    select vote.organization_id,
           vote.board_id,
           vote.id,
           vote.state,
           vote.row_version,
           vote.title,
           vote.close_mode,
           to_char(vote.deadline_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
           resolution.id,
           resolution.version,
           resolution.canonical_text,
           resolution.canonical_sha256,
           package.id,
           package.version,
           package.package_sha256,
           package.submission_manifest_sha256,
           package.document_manifest_sha256,
           package.question_cutoff_sha256,
           package.electorate_sha256,
           profile.id,
           profile.canonical_sha256,
           ruleset.id,
           ruleset.canonical_sha256,
           package.matter_evaluation_id,
           package.matter_evaluation_result_sha256,
           package.selected_ruleset_rule_id,
           package.selected_ruleset_rule_sha256,
           package.rule_override_id,
           package.rule_override_sha256,
           rule.id,
           rule.canonical_sha256,
           rule.threshold_numerator,
           rule.threshold_denominator,
           rule.quorum_numerator,
           rule.quorum_denominator,
           rule.approval_denominator,
           rule.abstentions_count_for_quorum,
           rule.tie_behavior,
           rule.proxy_policy,
           instance.instance_id,
           evidence_key.id,
           evidence_key.kid,
           evidence_key.public_jwk,
           evidence_key.nonsecret_locator,
           clock.id,
           to_char(clock.measured_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
           clock.drift_microseconds,
           to_char(clock.valid_until at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
           consent.record_sha256,
           (
             (transaction_scope = 'request' and boardagent_vote_actor_ready(vote.board_id))
             or
             (transaction_scope = 'worker'
               and vote.close_mode = 'automatic'
               and vote.deadline_at <= transaction_timestamp())
           ),
           (
             vote.current_resolution_version_id = resolution.id
             and vote.current_decision_package_id = package.id
             and vote.approval_rule_id = rule.id
             and vote.governance_profile_id = profile.id
             and vote.ruleset_id = ruleset.id
             and vote.electorate_sha256 = package.electorate_sha256
             and package.resolution_version_id = resolution.id
             and package.resolution_sha256 = resolution.canonical_sha256
             and package.approval_rule_id = rule.id
             and package.approval_rule_sha256 = rule.canonical_sha256
             and package.governance_profile_id = profile.id
             and package.governance_profile_sha256 = profile.canonical_sha256
             and package.ruleset_id = ruleset.id
             and package.ruleset_sha256 = ruleset.canonical_sha256
             and package.matter_evaluation_id = evaluation.id
             and package.matter_evaluation_result_sha256 = evaluation.result_sha256
             and package.selected_ruleset_rule_id = selected_rule.id
             and package.selected_ruleset_rule_sha256 = selected_rule.canonical_sha256
             and vote.matter_evaluation_id = package.matter_evaluation_id
             and vote.selected_ruleset_rule_id = package.selected_ruleset_rule_id
             and vote.rule_override_id is not distinct from package.rule_override_id
             and vote.rule_override_sha256 is not distinct from package.rule_override_sha256
             and (
               package.rule_override_id is null
               or (
                 rule_override.id = package.rule_override_id
                 and rule_override.canonical_sha256 = package.rule_override_sha256
                 and rule_override.evaluation_id = package.matter_evaluation_id
                 and rule_override.final_object_type = 'vote'
                 and rule_override.final_object_id = vote.id
                 and rule_override.selected_rule_id = package.selected_ruleset_rule_id
               )
             )
             and rule.close_mode = vote.close_mode
           ),
           (
             vote.state = 'open'
             and not exists (
               select 1
                 from vote_source_update_causes as cause
                 left join vote_source_update_dispositions as disposition
                   on disposition.cause_id = cause.id
                where cause.vote_id = vote.id
                  and disposition.id is null
             )
           ),
           boardagent_vote_qna_close_ready(vote.id),
           (
             clock.id is not null
             and clock.healthy
             and clock.measured_at <= transaction_timestamp()
             and clock.valid_until >= transaction_timestamp()
           ),
           (
             evidence_key.purpose = 'evidence_signing'
             and evidence_key.algorithm = 'EdDSA'
             and evidence_key.public_jwk is not null
             and evidence_key.activated_at <= transaction_timestamp()
             and (evidence_key.retired_at is null or evidence_key.retired_at > transaction_timestamp())
             and evidence_key.compromised_at is null
           ),
           (
             (
               transaction_scope = 'worker'
               and vote.close_mode = 'automatic'
               and candidate_consent is null
             )
             or
             (
               transaction_scope = 'request'
               and consent.id is not null
               and vote.close_mode = 'secretariat_confirmed'
               and consent.organization_id = vote.organization_id
               and consent.board_id = vote.board_id
               and consent.actor_member_id = boardagent_context_uuid('boardagent.member_id')
               and consent.client_id = boardagent_context_uuid('boardagent.client_id')
               and consent.token_jti = boardagent_context_uuid('boardagent.token_jti')
               and consent.action_code = 'close_vote'
               and consent.target_type = 'vote'
               and consent.target_id = vote.id
               and consent.payload_sha256 = candidate_consent_sha256
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
               and attempt.original_name = 'close_vote'
               and attempt.response_action = 'accept'
               and attempt.state = 'confirmed'
             )
           )
      from votes as vote
      join system_instance as instance on instance.organization_id = vote.organization_id
      join decision_packages as package
        on package.vote_id = vote.id and package.id = vote.current_decision_package_id
      join resolution_versions as resolution
        on resolution.vote_id = vote.id and resolution.id = vote.current_resolution_version_id
      join approval_rules as rule on rule.id = vote.approval_rule_id
      join governance_profiles as profile on profile.id = vote.governance_profile_id
      join rulesets as ruleset on ruleset.id = vote.ruleset_id
      join matter_evaluations as evaluation on evaluation.id = package.matter_evaluation_id
      join ruleset_rules as selected_rule on selected_rule.id = package.selected_ruleset_rule_id
      left join rule_overrides as rule_override on rule_override.id = package.rule_override_id
      join crypto_key_registry as evidence_key
        on evidence_key.id = candidate_signing_key
       and evidence_key.organization_id = vote.organization_id
      left join consent_records as consent on consent.id = candidate_consent
      left join action_stages as stage on stage.id = consent.stage_id
      left join input_required_attempts as attempt
        on attempt.id = consent.input_required_attempt_id
      left join lateral (
        select sample.*
          from clock_health_samples as sample
         where sample.organization_id = vote.organization_id
         order by sample.measured_at desc, sample.id desc
         limit 1
      ) as clock on true
     where vote.id = candidate_vote
       and (
         transaction_scope = 'worker'
         or (
           vote.organization_id = boardagent_context_uuid('boardagent.organization_id')
           and boardagent_context_board_allowed(vote.board_id)
         )
       )
     for update of vote
     for share of evidence_key;
end
$$;
alter function boardagent_lock_vote_for_close(uuid, uuid, bytea, uuid)
  owner to boardagent_migrator;
revoke all on function boardagent_lock_vote_for_close(uuid, uuid, bytea, uuid) from public;
grant execute on function boardagent_lock_vote_for_close(uuid, uuid, bytea, uuid)
  to boardagent_server, boardagent_worker;

create function boardagent_lock_closing_vote(
  candidate_organization uuid,
  candidate_vote uuid,
  candidate_outcome uuid,
  candidate_certificate uuid
)
returns table(
  organization_id uuid,
  board_id uuid,
  vote_id uuid,
  vote_state text,
  vote_row_version bigint,
  vote_title text,
  close_mode text,
  deadline_at text,
  resolution_version_id uuid,
  resolution_version integer,
  resolution_text text,
  resolution_sha256 bytea,
  decision_package_id uuid,
  decision_package_version integer,
  decision_package_sha256 bytea,
  submission_manifest_sha256 bytea,
  document_manifest_sha256 bytea,
  question_cutoff_sha256 bytea,
  electorate_sha256 bytea,
  governance_profile_id uuid,
  governance_profile_sha256 bytea,
  ruleset_id uuid,
  ruleset_sha256 bytea,
  matter_evaluation_id uuid,
  matter_evaluation_result_sha256 bytea,
  selected_ruleset_rule_id uuid,
  selected_ruleset_rule_sha256 bytea,
  rule_override_id uuid,
  rule_override_sha256 bytea,
  approval_rule_id uuid,
  approval_rule_sha256 bytea,
  threshold_numerator bigint,
  threshold_denominator bigint,
  quorum_numerator bigint,
  quorum_denominator bigint,
  approval_denominator text,
  abstentions_count_for_quorum boolean,
  tie_behavior text,
  proxy_policy text,
  instance_id uuid,
  signing_key_id uuid,
  signing_kid text,
  signing_public_jwk jsonb,
  signing_locator text,
  clock_sample_id uuid,
  clock_measured_at text,
  clock_drift_microseconds bigint,
  clock_valid_until text,
  close_consent_record_sha256 bytea,
  actor_ready boolean,
  package_binding_valid boolean,
  source_ready boolean,
  qna_ready boolean,
  clock_healthy boolean,
  key_valid boolean,
  consent_valid boolean,
  outcome_id uuid,
  certificate_id uuid,
  certificate_public_id bytea,
  canonical_certificate_payload bytea,
  certificate_payload_sha256 bytea,
  canonical_tally jsonb,
  tally_sha256 bytea,
  persisted_outcome text,
  close_actor_member_id uuid,
  close_consent_record_id uuid,
  closing_audit_event_id uuid,
  closing_audit_sequence bigint,
  closing_audit_hash bytea,
  closing_audit_occurred_at text,
  existing_signature bytea,
  existing_certificate_state text
)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
declare
  transaction_scope text;
begin
  transaction_scope := current_setting('boardagent.transaction_scope', true);
  if transaction_scope is distinct from 'request'
     and transaction_scope is distinct from 'worker' then
    raise exception 'certificate finalization requires a managed transaction'
      using errcode = '25000';
  end if;
  return query
    select vote.organization_id,
           vote.board_id,
           vote.id,
           vote.state,
           vote.row_version,
           vote.title,
           vote.close_mode,
           to_char(vote.deadline_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
           resolution.id,
           resolution.version,
           resolution.canonical_text,
           resolution.canonical_sha256,
           package.id,
           package.version,
           package.package_sha256,
           package.submission_manifest_sha256,
           package.document_manifest_sha256,
           package.question_cutoff_sha256,
           package.electorate_sha256,
           package.governance_profile_id,
           package.governance_profile_sha256,
           package.ruleset_id,
           package.ruleset_sha256,
           package.matter_evaluation_id,
           package.matter_evaluation_result_sha256,
           package.selected_ruleset_rule_id,
           package.selected_ruleset_rule_sha256,
           package.rule_override_id,
           package.rule_override_sha256,
           rule.id,
           rule.canonical_sha256,
           rule.threshold_numerator,
           rule.threshold_denominator,
           rule.quorum_numerator,
           rule.quorum_denominator,
           rule.approval_denominator,
           rule.abstentions_count_for_quorum,
           rule.tie_behavior,
           rule.proxy_policy,
           instance.instance_id,
           evidence_key.id,
           evidence_key.kid,
           evidence_key.public_jwk,
           evidence_key.nonsecret_locator,
           clock.id,
           to_char(clock.measured_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
           clock.drift_microseconds,
           to_char(clock.valid_until at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
           close_consent.record_sha256,
           true,
           true,
           true,
           true,
           true,
           (
             evidence_key.purpose = 'evidence_signing'
             and evidence_key.algorithm = 'EdDSA'
             and evidence_key.public_jwk is not null
             and evidence_key.activated_at <= transaction_timestamp()
             and (evidence_key.retired_at is null or evidence_key.retired_at > transaction_timestamp())
             and evidence_key.compromised_at is null
           ),
           true,
           outcome.id,
           outcome.certificate_id,
           outcome.certificate_public_id,
           outcome.canonical_certificate_payload,
           outcome.certificate_payload_sha256,
           outcome.canonical_tally,
           outcome.tally_sha256,
           outcome.outcome,
           outcome.close_actor_member_id,
           outcome.close_consent_record_id,
           outcome.closing_audit_event_id,
           closing.sequence,
           closing.event_sha256,
           to_char(closing.occurred_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
           certificate.signature,
           certificate.state
      from votes as vote
      join vote_outcomes as outcome
        on outcome.vote_id = vote.id
       and outcome.id = candidate_outcome
       and outcome.certificate_id = candidate_certificate
      join system_instance as instance on instance.organization_id = vote.organization_id
      join decision_packages as package on package.id = outcome.decision_package_id
      join resolution_versions as resolution on resolution.id = package.resolution_version_id
      join approval_rules as rule on rule.id = outcome.approval_rule_id
      join crypto_key_registry as evidence_key
        on evidence_key.id = outcome.signing_key_id
       and evidence_key.organization_id = vote.organization_id
      join clock_health_samples as clock on clock.id = outcome.clock_sample_id
      join audit_events as closing on closing.id = outcome.closing_audit_event_id
      left join consent_records as close_consent
        on close_consent.id = outcome.close_consent_record_id
      left join vote_certificates as certificate
        on certificate.vote_id = vote.id
       and certificate.outcome_id = outcome.id
       and certificate.id = outcome.certificate_id
     where vote.id = candidate_vote
       and vote.organization_id = candidate_organization
       and (
         (transaction_scope = 'worker' and vote.close_mode = 'automatic')
         or (
           candidate_organization = boardagent_context_uuid('boardagent.organization_id')
           and boardagent_context_board_allowed(vote.board_id)
           and vote.close_mode = 'secretariat_confirmed'
           and outcome.close_actor_member_id = boardagent_context_uuid('boardagent.member_id')
           and boardagent_vote_actor_ready(vote.board_id)
         )
       )
     for update of vote
     for share of evidence_key;
end
$$;
alter function boardagent_lock_closing_vote(uuid, uuid, uuid, uuid)
  owner to boardagent_migrator;
revoke all on function boardagent_lock_closing_vote(uuid, uuid, uuid, uuid) from public;
grant execute on function boardagent_lock_closing_vote(uuid, uuid, uuid, uuid)
  to boardagent_server, boardagent_worker;

create function boardagent_vote_close_evidence(
  candidate_organization uuid,
  candidate_vote uuid
)
returns table(
  electorate jsonb,
  exclusions jsonb,
  proxies jsonb,
  ballots jsonb
)
language plpgsql
stable
security definer
set search_path = pg_catalog, public
as $$
declare
  transaction_scope text;
  vote_row votes%rowtype;
begin
  transaction_scope := current_setting('boardagent.transaction_scope', true);
  if transaction_scope is distinct from 'request'
     and transaction_scope is distinct from 'worker' then
    raise exception 'vote close evidence requires a managed transaction'
      using errcode = '25000';
  end if;
  select * into strict vote_row
    from votes
   where id = candidate_vote
     and organization_id = candidate_organization;
  if vote_row.state not in ('open', 'closing', 'closed')
     or (
       transaction_scope = 'request'
       and (
         candidate_organization <> boardagent_context_uuid('boardagent.organization_id')
         or not boardagent_context_board_allowed(vote_row.board_id)
       )
     )
     or (transaction_scope = 'worker' and vote_row.close_mode <> 'automatic') then
    raise exception 'vote close evidence is unavailable' using errcode = '42501';
  end if;
  return query select
    coalesce((
      select jsonb_agg(jsonb_build_object(
        'id', row.id,
        'memberId', row.member_id,
        'membershipVersionId', row.membership_version_id,
        'seatRole', row.seat_role,
        'isChair', row.is_chair,
        'votingWeight', row.voting_weight::text,
        'eligibilitySnapshot', row.eligibility_snapshot,
        'eligibilitySha256', encode(row.eligibility_sha256, 'hex')
      ) order by row.member_id)
        from vote_electorate as row where row.vote_id = candidate_vote
    ), '[]'::jsonb),
    coalesce((
      select jsonb_agg(jsonb_build_object(
        'id', row.id,
        'memberId', row.member_id,
        'version', row.version,
        'state', row.state,
        'reason', row.reason,
        'actorMemberId', row.actor_member_id,
        'consentRecordId', row.consent_record_id,
        'consentRecordSha256', encode(consent.record_sha256, 'hex'),
        'effectiveAt', to_char(
          row.effective_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
        )
      ) order by row.member_id, row.version, row.id)
        from vote_exclusions as row
        join consent_records as consent on consent.id = row.consent_record_id
       where row.vote_id = candidate_vote
    ), '[]'::jsonb),
    coalesce((
      select jsonb_agg(jsonb_build_object(
        'id', row.id,
        'principalMemberId', row.principal_member_id,
        'holderMemberId', row.holder_member_id,
        'policy', row.policy,
        'consentRecordId', row.consent_record_id,
        'consentRecordSha256', encode(consent.record_sha256, 'hex'),
        'grantedAt', to_char(
          row.granted_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
        ),
        'expiresAt', case when row.expires_at is null then null else to_char(
          row.expires_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
        ) end,
        'revocation', case when revocation.id is null then null else jsonb_build_object(
          'id', revocation.id,
          'effect', revocation.effect,
          'consentRecordId', revocation.consent_record_id,
          'consentRecordSha256', case when revocation_consent.id is null then null
            else encode(revocation_consent.record_sha256, 'hex') end,
          'revokedAt', to_char(
            revocation.revoked_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
          )
        ) end
      ) order by row.id)
        from proxy_grants as row
        join consent_records as consent on consent.id = row.consent_record_id
        left join proxy_revocations as revocation on revocation.grant_id = row.id
        left join consent_records as revocation_consent
          on revocation_consent.id = revocation.consent_record_id
       where row.vote_id = candidate_vote
    ), '[]'::jsonb),
    coalesce((
      select jsonb_agg(jsonb_build_object(
        'id', row.id,
        'decisionPackageId', row.decision_package_id,
        'principalMemberId', row.principal_member_id,
        'casterMemberId', row.caster_member_id,
        'choice', row.choice,
        'statementText', row.statement_text,
        'statementSha256', case when row.statement_sha256 is null then null
          else encode(row.statement_sha256, 'hex') end,
        'votingWeight', row.voting_weight::text,
        'source', row.ballot_source,
        'proxyGrantId', row.proxy_grant_id,
        'consentRecordId', row.consent_record_id,
        'consentRecordSha256', encode(consent.record_sha256, 'hex'),
        'castAt', to_char(
          row.cast_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
        ),
        'disposition', case when disposition.id is null then null else jsonb_build_object(
          'id', disposition.id,
          'effect', disposition.effect,
          'supersedingBallotId', disposition.superseding_ballot_id,
          'replacementVoteId', disposition.replacement_vote_id,
          'auditEventId', disposition.audit_event_id,
          'createdAt', to_char(
            disposition.created_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
          )
        ) end
      ) order by row.principal_member_id, row.cast_at, row.id)
        from ballots as row
        join consent_records as consent on consent.id = row.consent_record_id
        left join ballot_dispositions as disposition on disposition.prior_ballot_id = row.id
       where row.vote_id = candidate_vote
    ), '[]'::jsonb);
end
$$;
alter function boardagent_vote_close_evidence(uuid, uuid) owner to boardagent_migrator;
revoke all on function boardagent_vote_close_evidence(uuid, uuid) from public;
grant execute on function boardagent_vote_close_evidence(uuid, uuid)
  to boardagent_server, boardagent_worker;

create function boardagent_guard_vote_outcome_insert()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  vote_row votes%rowtype;
  sample clock_health_samples%rowtype;
  closing_event audit_events%rowtype;
  evidence_key crypto_key_registry%rowtype;
begin
  select * into strict vote_row from votes where id = new.vote_id;
  select * into strict sample from clock_health_samples where id = new.clock_sample_id;
  select * into strict closing_event from audit_events where id = new.closing_audit_event_id;
  select * into strict evidence_key from crypto_key_registry where id = new.signing_key_id;
  if vote_row.state <> 'open'
     or vote_row.organization_id <> new.organization_id
     or vote_row.board_id <> new.board_id
     or vote_row.current_decision_package_id <> new.decision_package_id
     or vote_row.electorate_sha256 <> new.electorate_sha256
     or vote_row.approval_rule_id <> new.approval_rule_id
     or vote_row.close_mode <> new.close_mode then
    raise exception 'vote outcome does not bind the exact open vote'
      using errcode = '23514';
  end if;
  if sample.organization_id <> new.organization_id
     or not sample.healthy
     or sample.measured_at > transaction_timestamp()
     or sample.valid_until < transaction_timestamp() then
    raise exception 'vote outcome requires a current healthy clock sample'
      using errcode = '23514';
  end if;
  if closing_event.organization_id <> new.organization_id
     or closing_event.board_id is distinct from new.board_id
     or closing_event.event_type <> 'vote_closing'
     or closing_event.object_type <> 'vote'
     or closing_event.object_id is distinct from new.vote_id then
    raise exception 'vote outcome requires its exact vote_closing audit event'
      using errcode = '23514';
  end if;
  if evidence_key.organization_id <> new.organization_id
     or evidence_key.purpose <> 'evidence_signing'
     or evidence_key.algorithm <> 'EdDSA'
     or evidence_key.public_jwk is null
     or evidence_key.activated_at > transaction_timestamp()
     or (evidence_key.retired_at is not null and evidence_key.retired_at <= transaction_timestamp())
     or evidence_key.compromised_at is not null then
    raise exception 'vote outcome requires an active uncompromised Ed25519 evidence key'
      using errcode = '23514';
  end if;
  if new.close_mode = 'secretariat_confirmed' and not exists (
    select 1
      from consent_records as consent
     where consent.id = new.close_consent_record_id
       and consent.organization_id = new.organization_id
       and consent.board_id = new.board_id
       and consent.actor_member_id = new.close_actor_member_id
       and consent.action_code = 'close_vote'
       and consent.target_type = 'vote'
       and consent.target_id = new.vote_id
       and consent.payload_sha256 = new.close_request_sha256
       and consent.package_sha256 = (
         select package.package_sha256
           from decision_packages as package
          where package.id = new.decision_package_id
            and package.vote_id = new.vote_id
       )
  ) then
    raise exception 'vote outcome requires exact close consent'
      using errcode = '23514';
  end if;
  if (new.close_mode = 'secretariat_confirmed' and (
        closing_event.actor_member_id is distinct from new.close_actor_member_id
        or closing_event.consent_record_id is distinct from new.close_consent_record_id
      ))
     or (new.close_mode = 'automatic' and (
        closing_event.actor_member_id is not null
        or closing_event.consent_record_id is not null
      )) then
    raise exception 'vote_closing audit attribution does not match close mode'
      using errcode = '23514';
  end if;
  if exists (
    select 1
      from vote_source_update_causes as cause
      left join vote_source_update_dispositions as disposition on disposition.cause_id = cause.id
     where cause.vote_id = new.vote_id and disposition.id is null
  ) or not boardagent_vote_qna_close_ready(new.vote_id) then
    raise exception 'vote outcome requires every source and linked Q&A close precondition'
      using errcode = '23514';
  end if;
  return new;
end
$$;
alter function boardagent_guard_vote_outcome_insert() owner to boardagent_migrator;
revoke all on function boardagent_guard_vote_outcome_insert() from public;
create trigger boardagent_vote_outcome_insert_guard
  before insert on vote_outcomes
  for each row execute function boardagent_guard_vote_outcome_insert();

create function boardagent_commit_vote_close_draft(
  candidate_organization uuid,
  candidate_vote uuid,
  candidate_outcome uuid,
  candidate_certificate uuid,
  candidate_public_id bytea,
  candidate_package uuid,
  candidate_electorate_sha256 bytea,
  candidate_approval_rule uuid,
  candidate_tally jsonb,
  candidate_tally_sha256 bytea,
  candidate_outcome_value text,
  candidate_close_mode text,
  candidate_actor uuid,
  candidate_consent uuid,
  candidate_payload bytea,
  candidate_payload_sha256 bytea,
  candidate_signing_key uuid,
  candidate_clock_sample uuid,
  candidate_closing_event uuid,
  candidate_close_request_sha256 bytea
)
returns table(vote_id uuid, outcome_id uuid, state text, row_version bigint)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
declare
  transaction_scope text;
  vote_row votes%rowtype;
begin
  transaction_scope := current_setting('boardagent.transaction_scope', true);
  if transaction_scope is distinct from 'request'
     and transaction_scope is distinct from 'worker' then
    raise exception 'vote close draft requires a managed transaction'
      using errcode = '25000';
  end if;
  select * into strict vote_row from votes where id = candidate_vote for update;
  if vote_row.organization_id <> candidate_organization then
    raise exception 'vote close draft is unavailable' using errcode = '42501';
  end if;
  if transaction_scope = 'request' and (
    candidate_organization <> boardagent_context_uuid('boardagent.organization_id')
    or not boardagent_context_board_allowed(vote_row.board_id)
    or not boardagent_vote_actor_ready(vote_row.board_id)
    or candidate_close_mode <> 'secretariat_confirmed'
    or candidate_actor is distinct from boardagent_context_uuid('boardagent.member_id')
    or candidate_consent is null
  ) then
    raise exception 'confirmed vote close draft is unavailable' using errcode = '42501';
  end if;
  if transaction_scope = 'worker' and (
    candidate_close_mode <> 'automatic'
    or candidate_actor is not null
    or candidate_consent is not null
    or vote_row.close_mode <> 'automatic'
    or vote_row.deadline_at > transaction_timestamp()
  ) then
    raise exception 'automatic vote close draft is unavailable' using errcode = '42501';
  end if;
  insert into vote_outcomes(
    id, organization_id, board_id, vote_id, decision_package_id,
    electorate_sha256, approval_rule_id, canonical_tally, tally_sha256, outcome,
    close_mode, close_actor_member_id, close_consent_record_id,
    certificate_id, certificate_public_id, canonical_certificate_payload,
    certificate_payload_sha256, signing_key_id, clock_sample_id,
    closing_audit_event_id, close_request_sha256
  ) values (
    candidate_outcome, candidate_organization, vote_row.board_id, candidate_vote,
    candidate_package, candidate_electorate_sha256, candidate_approval_rule,
    candidate_tally, candidate_tally_sha256, candidate_outcome_value,
    candidate_close_mode, candidate_actor, candidate_consent,
    candidate_certificate, candidate_public_id, candidate_payload,
    candidate_payload_sha256, candidate_signing_key, candidate_clock_sample,
    candidate_closing_event, candidate_close_request_sha256
  );
  update votes as target
     set state = 'closing', row_version = target.row_version + 1
   where target.id = candidate_vote and target.state = 'open';
  if not found then
    raise exception 'vote close draft lost its open vote' using errcode = '40001';
  end if;
  return query
    select vote.id, candidate_outcome, vote.state, vote.row_version
      from votes as vote where vote.id = candidate_vote;
end
$$;
alter function boardagent_commit_vote_close_draft(
  uuid, uuid, uuid, uuid, bytea, uuid, bytea, uuid, jsonb, bytea, text,
  text, uuid, uuid, bytea, bytea, uuid, uuid, uuid, bytea
) owner to boardagent_migrator;
revoke all on function boardagent_commit_vote_close_draft(
  uuid, uuid, uuid, uuid, bytea, uuid, bytea, uuid, jsonb, bytea, text,
  text, uuid, uuid, bytea, bytea, uuid, uuid, uuid, bytea
) from public;
grant execute on function boardagent_commit_vote_close_draft(
  uuid, uuid, uuid, uuid, bytea, uuid, bytea, uuid, jsonb, bytea, text,
  text, uuid, uuid, bytea, bytea, uuid, uuid, uuid, bytea
) to boardagent_server, boardagent_worker;

create function boardagent_guard_vote_certificate_insert()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  vote_row votes%rowtype;
  outcome_row vote_outcomes%rowtype;
  issued_event audit_events%rowtype;
  closed_event audit_events%rowtype;
begin
  select * into strict vote_row from votes where id = new.vote_id;
  select * into strict outcome_row from vote_outcomes where id = new.outcome_id;
  select * into strict issued_event from audit_events
   where id = new.certificate_issued_audit_event_id;
  select * into strict closed_event from audit_events
   where id = new.vote_closed_audit_event_id;
  if vote_row.state <> 'closing'
     or vote_row.organization_id <> new.organization_id
     or vote_row.board_id <> new.board_id
     or outcome_row.vote_id <> new.vote_id
     or outcome_row.organization_id <> new.organization_id
     or outcome_row.board_id <> new.board_id
     or outcome_row.certificate_id <> new.id
     or outcome_row.certificate_public_id <> new.public_id
     or outcome_row.canonical_certificate_payload <> new.canonical_payload
     or outcome_row.certificate_payload_sha256 <> new.payload_sha256
     or outcome_row.signing_key_id <> new.signing_key_id then
    raise exception 'vote certificate does not match its immutable closing draft'
      using errcode = '23514';
  end if;
  if issued_event.event_type <> 'certificate_issued'
     or closed_event.event_type <> 'vote_closed'
     or issued_event.organization_id <> new.organization_id
     or closed_event.organization_id <> new.organization_id
     or issued_event.board_id is distinct from new.board_id
     or closed_event.board_id is distinct from new.board_id
     or issued_event.object_type <> 'vote'
     or closed_event.object_type <> 'vote'
     or issued_event.object_id is distinct from new.vote_id
     or closed_event.object_id is distinct from new.vote_id then
    raise exception 'vote certificate requires exact issuance and closure audit events'
      using errcode = '23514';
  end if;
  if (outcome_row.close_mode = 'secretariat_confirmed' and (
        issued_event.actor_member_id is distinct from outcome_row.close_actor_member_id
        or closed_event.actor_member_id is distinct from outcome_row.close_actor_member_id
      ))
     or (outcome_row.close_mode = 'automatic' and (
        issued_event.actor_member_id is not null
        or closed_event.actor_member_id is not null
      )) then
    raise exception 'certificate audit attribution does not match close mode'
      using errcode = '23514';
  end if;
  return new;
end
$$;
alter function boardagent_guard_vote_certificate_insert() owner to boardagent_migrator;
revoke all on function boardagent_guard_vote_certificate_insert() from public;
create trigger boardagent_vote_certificate_insert_guard
  before insert on vote_certificates
  for each row execute function boardagent_guard_vote_certificate_insert();

create function boardagent_guard_vote_certificate_state()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  if old.state = 'open' and new.state = 'closing' and not exists (
    select 1
      from vote_outcomes as outcome
     where outcome.vote_id = old.id
       and outcome.organization_id = old.organization_id
       and outcome.board_id = old.board_id
       and outcome.decision_package_id = old.current_decision_package_id
       and outcome.electorate_sha256 = old.electorate_sha256
       and outcome.approval_rule_id = old.approval_rule_id
       and outcome.close_mode = old.close_mode
  ) then
    raise exception 'vote cannot enter closing without its immutable outcome and certificate draft'
      using errcode = '23514';
  end if;
  if old.state = 'closing' and new.state = 'closed' and not exists (
    select 1
      from vote_certificates as certificate
      join vote_outcomes as outcome on outcome.id = certificate.outcome_id
     where certificate.vote_id = old.id
       and certificate.organization_id = old.organization_id
       and certificate.board_id = old.board_id
       and outcome.vote_id = old.id
  ) then
    raise exception 'vote cannot close without its signed certificate'
      using errcode = '23514';
  end if;
  return new;
end
$$;
alter function boardagent_guard_vote_certificate_state() owner to boardagent_migrator;
revoke all on function boardagent_guard_vote_certificate_state() from public;
create trigger boardagent_vote_certificate_state_guard
  before update of state on votes
  for each row execute function boardagent_guard_vote_certificate_state();

create function boardagent_assert_outcome_vote_state()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  if not exists (
    select 1
      from votes as vote
     where vote.id = new.vote_id
       and vote.state in ('closing', 'closed')
       and vote.organization_id = new.organization_id
       and vote.board_id = new.board_id
       and vote.current_decision_package_id = new.decision_package_id
  ) then
    raise exception 'committed vote outcome must belong to a closing or closed vote'
      using errcode = '23514';
  end if;
  return null;
end
$$;
alter function boardagent_assert_outcome_vote_state() owner to boardagent_migrator;
revoke all on function boardagent_assert_outcome_vote_state() from public;
create constraint trigger boardagent_outcome_vote_state_guard
  after insert on vote_outcomes
  deferrable initially deferred
  for each row execute function boardagent_assert_outcome_vote_state();

create function boardagent_assert_certificate_vote_state()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  if not exists (
    select 1
      from votes as vote
     where vote.id = new.vote_id
       and vote.state = 'closed'
       and vote.organization_id = new.organization_id
       and vote.board_id = new.board_id
  ) then
    raise exception 'committed vote certificate must belong to a closed vote'
      using errcode = '23514';
  end if;
  return null;
end
$$;
alter function boardagent_assert_certificate_vote_state() owner to boardagent_migrator;
revoke all on function boardagent_assert_certificate_vote_state() from public;
create constraint trigger boardagent_certificate_vote_state_guard
  after insert on vote_certificates
  deferrable initially deferred
  for each row execute function boardagent_assert_certificate_vote_state();

create function boardagent_commit_vote_certificate(
  candidate_organization uuid,
  candidate_vote uuid,
  candidate_outcome uuid,
  candidate_certificate uuid,
  candidate_public_id bytea,
  candidate_payload bytea,
  candidate_payload_sha256 bytea,
  candidate_signature bytea,
  candidate_signing_key uuid,
  candidate_issued_event uuid,
  candidate_closed_event uuid
)
returns table(vote_id uuid, certificate_id uuid, state text, closed_at text)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
declare
  transaction_scope text;
  vote_row votes%rowtype;
  outcome_row vote_outcomes%rowtype;
begin
  transaction_scope := current_setting('boardagent.transaction_scope', true);
  if transaction_scope is distinct from 'request'
     and transaction_scope is distinct from 'worker' then
    raise exception 'certificate commit requires a managed transaction'
      using errcode = '25000';
  end if;
  select * into strict vote_row from votes where id = candidate_vote for update;
  select outcome.* into strict outcome_row from vote_outcomes as outcome
   where outcome.id = candidate_outcome and outcome.vote_id = candidate_vote;
  if vote_row.organization_id <> candidate_organization
     or (
       transaction_scope = 'request'
       and (
         candidate_organization <> boardagent_context_uuid('boardagent.organization_id')
         or not boardagent_context_board_allowed(vote_row.board_id)
         or vote_row.close_mode <> 'secretariat_confirmed'
         or outcome_row.close_actor_member_id is distinct from
              boardagent_context_uuid('boardagent.member_id')
         or not boardagent_vote_actor_ready(vote_row.board_id)
       )
     )
     or (transaction_scope = 'worker' and vote_row.close_mode <> 'automatic') then
    raise exception 'certificate commit is unavailable' using errcode = '42501';
  end if;
  if vote_row.state = 'closed' then
    return query
      select certificate.vote_id,
             certificate.id,
             vote_row.state,
             to_char(vote_row.closed_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
        from vote_certificates as certificate
       where certificate.id = candidate_certificate
         and certificate.vote_id = candidate_vote
         and certificate.outcome_id = candidate_outcome
         and certificate.public_id = candidate_public_id
         and certificate.canonical_payload = candidate_payload
         and certificate.payload_sha256 = candidate_payload_sha256
         and certificate.signature = candidate_signature
         and certificate.signing_key_id = candidate_signing_key;
    return;
  end if;
  if vote_row.state <> 'closing'
     or outcome_row.certificate_id <> candidate_certificate
     or outcome_row.certificate_public_id <> candidate_public_id
     or outcome_row.canonical_certificate_payload <> candidate_payload
     or outcome_row.certificate_payload_sha256 <> candidate_payload_sha256
     or outcome_row.signing_key_id <> candidate_signing_key then
    raise exception 'certificate commit does not match the closing vote'
      using errcode = '23514';
  end if;
  insert into vote_certificates(
    id, organization_id, board_id, vote_id, outcome_id, public_id, schema_version,
    canonical_payload, payload_sha256, signature, signing_key_id,
    certificate_issued_audit_event_id, vote_closed_audit_event_id
  ) values (
    candidate_certificate, candidate_organization, vote_row.board_id, candidate_vote,
    candidate_outcome, candidate_public_id, 'boardagent.vote-certificate.v1',
    candidate_payload, candidate_payload_sha256, candidate_signature, candidate_signing_key,
    candidate_issued_event, candidate_closed_event
  );
  update votes as target
     set state = 'closed',
         closed_at = transaction_timestamp(),
         row_version = target.row_version + 1
   where target.id = candidate_vote and target.state = 'closing';
  return query
    select vote.id,
           candidate_certificate,
           vote.state,
           to_char(vote.closed_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
      from votes as vote
     where vote.id = candidate_vote;
end
$$;
alter function boardagent_commit_vote_certificate(
  uuid, uuid, uuid, uuid, bytea, bytea, bytea, bytea, uuid, uuid, uuid
) owner to boardagent_migrator;
revoke all on function boardagent_commit_vote_certificate(
  uuid, uuid, uuid, uuid, bytea, bytea, bytea, bytea, uuid, uuid, uuid
) from public;
grant execute on function boardagent_commit_vote_certificate(
  uuid, uuid, uuid, uuid, bytea, bytea, bytea, bytea, uuid, uuid, uuid
) to boardagent_server, boardagent_worker;

-- Workers already hold the audit insert capability, but the original protected
-- head reader admitted request transactions only.
create or replace function boardagent_lock_audit_head()
returns table(last_sequence bigint, last_event_sha256 bytea, occurred_at text)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request'
     and current_setting('boardagent.transaction_scope', true) is distinct from 'worker' then
    raise exception 'audit append requires a managed request transaction or worker transaction'
      using errcode = '25000';
  end if;
  return query
    select head.last_sequence,
           head.last_event_sha256,
           to_char(
             transaction_timestamp() at time zone 'UTC',
             'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
           )
      from audit_chain_head as head
     where head.singleton_key
       for update;
  if not found then
    raise exception 'audit chain head is unavailable' using errcode = '55000';
  end if;
end
$$;
alter function boardagent_lock_audit_head() owner to boardagent_migrator;
revoke all on function boardagent_lock_audit_head() from public;
grant execute on function boardagent_lock_audit_head() to boardagent_server, boardagent_worker;
