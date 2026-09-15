-- BoardAgent Phase 4 / group 75: bounded certificate recovery authority.

-- A recovery job carries only the vote identity. Resolve its already-frozen outcome and
-- certificate IDs without granting the worker table enumeration or direct mutation.
create function public.boardagent_closing_vote_recovery_identity(
  candidate_organization uuid,
  candidate_vote uuid
)
returns table(outcome_id uuid,certificate_id uuid,vote_state text)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker' then
    raise exception 'certificate recovery identity requires a managed worker transaction'
      using errcode='25000';
  end if;
  return query
    select outcome.id,outcome.certificate_id,vote.state
      from public.votes as vote
      join public.vote_outcomes as outcome
        on outcome.vote_id=vote.id and outcome.organization_id=vote.organization_id
     where vote.id=candidate_vote
       and vote.organization_id=candidate_organization
       and vote.state in ('closing','closed');
end
$$;
alter function public.boardagent_closing_vote_recovery_identity(uuid,uuid)
  owner to boardagent_migrator;
revoke all on function public.boardagent_closing_vote_recovery_identity(uuid,uuid) from public;
grant execute on function public.boardagent_closing_vote_recovery_identity(uuid,uuid)
  to boardagent_worker;

-- Finalization originally admitted the worker only for automatic votes. Once a manual
-- close has durably entered `closing`, its human consent and exact payload are already
-- frozen; the worker must be able to re-sign that same payload after a signer crash.
create or replace function public.boardagent_lock_closing_vote(
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
         (transaction_scope = 'worker' and vote.state in ('closing','closed'))
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

-- The original evidence reader allowed worker access only while an automatic vote was
-- open. Recovery must also recompute an already-frozen closing draft regardless of how
-- the close was initiated; it still cannot expose an open manual-close vote.
create or replace function public.boardagent_vote_close_evidence(
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
     or (
       transaction_scope = 'worker'
       and vote_row.close_mode <> 'automatic'
       and vote_row.state <> 'closing'
     ) then
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

-- Permit the worker to commit only a pre-existing closing/closed draft. Every identity,
-- canonical byte, digest, signature and evidence key still has to match that frozen row.
create or replace function public.boardagent_commit_vote_certificate(
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
     or (
       transaction_scope = 'worker'
       and vote_row.state not in ('closing','closed')
     ) then
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
