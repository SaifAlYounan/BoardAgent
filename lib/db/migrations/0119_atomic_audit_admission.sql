-- Admit an indivisible business transaction while signing debt is below 1000.
-- Bound its complete audit effect to 10000 events and 16 MiB of canonical payloads.
-- Actual database transaction identity and server incarnation own this allowance;
-- caller flags, later transactions and restored stale coordination state do not.
alter table public.audit_chain_head
  add column admission_transaction_id xid8,
  add column admission_server_start timestamptz,
  add column admission_start_sequence bigint not null default 0,
  add column admission_payload_bytes bigint not null default 0,
  add constraint boardagent_audit_admission_shape check (
    admission_start_sequence between 0 and last_sequence
    and admission_payload_bytes between 0 and 16777216
    and ((admission_transaction_id is null and admission_server_start is null)
      or (admission_transaction_id is not null and admission_server_start is not null))
  );

create or replace function public.boardagent_guard_audit_checkpoint_capacity()
returns trigger
language plpgsql
security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare
  head public.audit_chain_head%rowtype;
  checkpoint_head bigint;
  body jsonb;
  transaction_id xid8 := pg_current_xact_id();
  server_start timestamptz := pg_postmaster_start_time();
  admitted_start bigint;
  admitted_bytes bigint;
begin
  select * into strict head from public.audit_chain_head where singleton_key for update;
  -- The only special append is a checkpoint's matching, single-use attestation.
  -- It cannot establish ordinary transaction admission while signing debt is full.
  if new.event_type='audit_checkpoint_signed' and new.object_type='audit_checkpoint'
     and new.sequence=head.last_sequence+1
     and new.actor_member_id is null and new.client_id is null and new.token_jti is null
     and new.board_id is null then
    body := convert_from(new.canonical_payload,'UTF8')::jsonb;
    if body->>'origin'='worker' and body->>'entityId'=new.object_id::text
       and exists (
         select 1 from public.audit_checkpoints as checkpoint
          where checkpoint.id=new.object_id
            and checkpoint.organization_id=new.organization_id
            and checkpoint.attestation_transaction_id=transaction_id
            and checkpoint.attestation_sequence=new.sequence
            and body->'details'=jsonb_build_object(
              'manifestSha256',encode(checkpoint.manifest_sha256,'hex'),
              'firstSequence',checkpoint.first_sequence::text,
              'lastSequence',checkpoint.last_sequence::text,
              'signedHeadSha256',encode(checkpoint.last_event_sha256,'hex'),
              'signingKeyId',checkpoint.signing_key_id::text)
       ) then
      return new;
    end if;
  end if;

  if head.admission_transaction_id=transaction_id
     and head.admission_server_start=server_start then
    admitted_start := head.admission_start_sequence;
    admitted_bytes := head.admission_payload_bytes;
  else
    select coalesce(max(checkpoint.last_sequence),0) into checkpoint_head
      from public.audit_checkpoints as checkpoint;
    if head.last_sequence-checkpoint_head>=1000 then
      raise exception 'audit checkpoint capacity exhausted; retry after a signed checkpoint'
        using errcode='55000',constraint='boardagent_audit_checkpoint_capacity';
    end if;
    admitted_start := head.last_sequence;
    admitted_bytes := 0;
  end if;

  if head.last_sequence-admitted_start>=10000
     or admitted_bytes+octet_length(new.canonical_payload)>16777216 then
    raise exception 'audit effect exceeds the supported atomic action size'
      using errcode='54000',constraint='boardagent_audit_transaction_capacity';
  end if;

  update public.audit_chain_head set
    admission_transaction_id=transaction_id,
    admission_server_start=server_start,
    admission_start_sequence=admitted_start,
    admission_payload_bytes=admitted_bytes+octet_length(new.canonical_payload)
    where singleton_key;
  return new;
end;
$$;
alter function public.boardagent_guard_audit_checkpoint_capacity() owner to boardagent_migrator;
revoke all on function public.boardagent_guard_audit_checkpoint_capacity() from public;
