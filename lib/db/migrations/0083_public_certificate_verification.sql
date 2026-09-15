-- BoardAgent Phase 5: public certificate verification through one opaque capability.
--
-- The server may submit only the 256-bit public certificate reference. The definer
-- resolves the closed/current certificate and returns the exact persisted close inputs
-- needed by the shared TypeScript recomputation kernel. No lookup by vote, board,
-- member, title or other enumerable identifier is exposed.

create function public.boardagent_public_certificate_snapshot(candidate_public_id bytea)
returns jsonb
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
declare
  candidate_organization uuid;
  candidate_vote uuid;
  candidate_outcome uuid;
  candidate_certificate uuid;
  candidate_issued_at timestamptz;
  prior_scope text;
  prior_organization text;
  prior_boards text;
  close_snapshot jsonb;
  evidence_snapshot jsonb;
begin
  if candidate_public_id is null or octet_length(candidate_public_id) <> 32 then
    return null;
  end if;

  select certificate.organization_id,certificate.vote_id,certificate.outcome_id,certificate.id,
         certificate.issued_at
    into candidate_organization,candidate_vote,candidate_outcome,candidate_certificate,
         candidate_issued_at
    from public.vote_certificates as certificate
    join public.votes as vote
      on vote.id=certificate.vote_id
     and vote.organization_id=certificate.organization_id
   where certificate.public_id=candidate_public_id
     and certificate.state='current'
     and vote.state='closed';
  if not found then
    return null;
  end if;

  -- Reuse the already-frozen close snapshot contract. The scope is restored before
  -- returning, and this wrapper exposes no caller-selected internal identifiers.
  prior_scope := current_setting('boardagent.transaction_scope',true);
  prior_organization := current_setting('boardagent.organization_id',true);
  prior_boards := current_setting('boardagent.board_ids',true);
  perform set_config('boardagent.transaction_scope','worker',true);
  select to_jsonb(snapshot) || jsonb_build_object(
           'vote_row_version',snapshot.vote_row_version::text,
           'threshold_numerator',snapshot.threshold_numerator::text,
           'threshold_denominator',snapshot.threshold_denominator::text,
           'quorum_numerator',snapshot.quorum_numerator::text,
           'quorum_denominator',snapshot.quorum_denominator::text,
           'clock_drift_microseconds',snapshot.clock_drift_microseconds::text,
           'closing_audit_sequence',snapshot.closing_audit_sequence::text,
           'existing_certificate_issued_at',
             to_char(candidate_issued_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
         )
    into close_snapshot
    from public.boardagent_lock_closing_vote(
      candidate_organization,candidate_vote,candidate_outcome,candidate_certificate
    ) as snapshot;
  if close_snapshot is null then
    perform set_config('boardagent.transaction_scope',coalesce(prior_scope,''),true);
    return null;
  end if;

  -- Re-enter the existing request-scoped evidence reader with context derived only
  -- from the unguessable certificate capability, then restore the caller's context.
  perform set_config('boardagent.organization_id',candidate_organization::text,true);
  perform set_config(
    'boardagent.board_ids',jsonb_build_array(close_snapshot->>'board_id')::text,true
  );
  perform set_config('boardagent.transaction_scope','request',true);
  select to_jsonb(evidence)
    into evidence_snapshot
    from public.boardagent_vote_close_evidence(
      candidate_organization,candidate_vote
    ) as evidence;
  perform set_config('boardagent.transaction_scope',coalesce(prior_scope,''),true);
  perform set_config('boardagent.organization_id',coalesce(prior_organization,''),true);
  perform set_config('boardagent.board_ids',coalesce(prior_boards,''),true);
  if evidence_snapshot is null then
    return null;
  end if;

  return jsonb_build_object('row',close_snapshot,'evidence',evidence_snapshot);
end
$$;

alter function public.boardagent_public_certificate_snapshot(bytea)
  owner to boardagent_migrator;
revoke all on function public.boardagent_public_certificate_snapshot(bytea) from public;
grant execute on function public.boardagent_public_certificate_snapshot(bytea)
  to boardagent_server;
