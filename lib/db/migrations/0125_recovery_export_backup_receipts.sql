-- Preserve completed signing-outage findings in versioned backup/restore receipts.
-- Historical v1 receipts remain exact v1; recovery-aware boundaries require v2.
alter table public.backup_receipts
  drop constraint backup_receipts_schema_version_check,
  drop constraint backup_receipts_kind_state_check,
  add constraint backup_receipts_schema_version_check check (
    schema_version in ('boardagent.backup-receipt.v1','boardagent.restore-receipt.v1',
                       'boardagent.backup-receipt.v2','boardagent.restore-receipt.v2')
  ),
  add constraint backup_receipts_kind_state_check check (
    (receipt_kind='backup' and schema_version in ('boardagent.backup-receipt.v1','boardagent.backup-receipt.v2')
      and state in ('created','failed') and source_backup_receipt_id is null)
    or
    (receipt_kind='restore' and schema_version in ('boardagent.restore-receipt.v1','boardagent.restore-receipt.v2')
      and state in ('verified','failed') and source_backup_receipt_id is not null)
  );

-- A later recovery must not retroactively change an older backup's findings.
-- Its committed final head must be inside that backup's captured chain boundary.
-- Internal helper only; no additional runtime execution privilege.
create function public.boardagent_recovery_evidence_at_head(candidate_organization_id uuid, candidate_head bigint)
returns jsonb language sql stable security definer
set search_path=pg_catalog,public,pg_temp
as $$
  select coalesce(jsonb_agg(jsonb_build_object(
    'payload',convert_from(checkpoint.canonical_manifest,'UTF8')::jsonb,
    'signatureBase64Url',rtrim(translate(replace(encode(checkpoint.signature,'base64'),E'\n',''),'+/','-_'),'=')
  ) order by recovery.first_sequence),'[]'::jsonb)
  from public.audit_recoveries as recovery
  join public.audit_recovery_completions as completion on completion.recovery_id=recovery.id
  join public.audit_checkpoints as checkpoint
    on checkpoint.recovery_id=recovery.id and checkpoint.first_sequence=recovery.first_sequence
  where recovery.organization_id=candidate_organization_id and completion.final_head_sequence<=candidate_head;
$$;
alter function public.boardagent_recovery_evidence_at_head(uuid,bigint) owner to boardagent_migrator;
revoke all on function public.boardagent_recovery_evidence_at_head(uuid,bigint) from public;

create or replace function public.boardagent_guard_backup_receipt_insert()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  manifest jsonb;
  instance_row system_instance%rowtype;
  encryption_key crypto_key_registry%rowtype;
  source_receipt backup_receipts%rowtype;
  expected_recovery jsonb;
begin
  begin
    manifest := convert_from(new.canonical_manifest, 'UTF8')::jsonb;
  exception when others then
    raise exception 'backup or restore receipt manifest is not valid UTF-8 JSON evidence'
      using errcode = '23514';
  end;
  select * into strict instance_row from system_instance where singleton_key;
  select * into strict encryption_key from crypto_key_registry where id=new.encryption_key_id;
  if new.organization_id<>instance_row.organization_id
     or encryption_key.organization_id<>new.organization_id
     or encryption_key.purpose<>'backup_kek'
     or encryption_key.algorithm<>'A256GCM'
     or encryption_key.public_jwk is not null
     or encryption_key.activated_at>new.snapshot_at
     or (encryption_key.retired_at is not null and encryption_key.retired_at<=new.snapshot_at)
     or (encryption_key.compromised_at is not null and encryption_key.compromised_at<=new.snapshot_at)
     or manifest->>'receiptId'<>new.id::text
     or manifest->>'instanceId'<>instance_row.instance_id::text
     or manifest->>'organizationId'<>new.organization_id::text
     or manifest->>'snapshotLsn'<>new.snapshot_lsn::text
     or manifest->>'snapshotAt'<>to_char(
       new.snapshot_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
     )
     or manifest->>'contentSetSha256'<>encode(new.content_set_sha256,'hex')
     or manifest->>'encryptionKeyId'<>new.encryption_key_id::text
     or new.manifest_sha256<>sha256(new.canonical_manifest) then
    raise exception 'backup or restore receipt does not bind its instance, boundary and backup key'
      using errcode = '23514';
  end if;
  if new.receipt_kind='backup' then
    if manifest->>'schemaVersion' is distinct from new.schema_version
       or new.schema_version not in ('boardagent.backup-receipt.v1','boardagent.backup-receipt.v2')
       or manifest->>'receiptKind'<>'backup' then
      raise exception 'backup receipt manifest fields differ from the evidence row'
        using errcode = '23514';
    end if;
  else
    select * into strict source_receipt from backup_receipts where id=new.source_backup_receipt_id;
    if source_receipt.receipt_kind<>'backup'
       or source_receipt.organization_id<>new.organization_id
       or manifest->>'schemaVersion' is distinct from new.schema_version
       or new.schema_version not in ('boardagent.restore-receipt.v1','boardagent.restore-receipt.v2')
       or manifest->>'receiptKind'<>'restore'
       or manifest->>'sourceBackupReceiptId'<>source_receipt.id::text
       or manifest->>'sourceBackupManifestSha256'<>encode(source_receipt.manifest_sha256,'hex')
       or manifest->>'verifiedAt'<>to_char(
         new.verified_restore_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
       )
       or new.snapshot_lsn<>source_receipt.snapshot_lsn
       or new.snapshot_at<>source_receipt.snapshot_at
       or new.content_set_sha256<>source_receipt.content_set_sha256
       or new.encryption_key_id<>source_receipt.encryption_key_id then
      raise exception 'restore receipt does not bind an immutable source backup receipt'
        using errcode = '23514';
    end if;
  end if;
  if new.receipt_kind='backup' then
    if coalesce(manifest#>>'{auditBoundary,eventCount}','') !~ '^(0|[1-9][0-9]{0,18})$' then
      raise exception 'backup audit boundary is invalid' using errcode='23514';
    end if;
    expected_recovery:=public.boardagent_recovery_evidence_at_head(
      new.organization_id,(manifest#>>'{auditBoundary,eventCount}')::bigint
    );
  else
    expected_recovery:=coalesce(
      convert_from(source_receipt.canonical_manifest,'UTF8')::jsonb->'auditRecoveryEvidence','[]'::jsonb
    );
  end if;
  if (expected_recovery='[]'::jsonb and (
        new.schema_version not in ('boardagent.backup-receipt.v1','boardagent.restore-receipt.v1')
        or manifest ? 'auditRecoveryEvidence'))
     or (expected_recovery<>'[]'::jsonb and (
        new.schema_version not in ('boardagent.backup-receipt.v2','boardagent.restore-receipt.v2')
        or manifest->'auditRecoveryEvidence' is distinct from expected_recovery)) then
    raise exception 'receipt must preserve the completed recovery evidence at its original boundary'
      using errcode='23514';
  end if;
  return new;
end;
$$;
alter function boardagent_guard_backup_receipt_insert() owner to boardagent_migrator;
revoke all on function boardagent_guard_backup_receipt_insert() from public;

create or replace function public.boardagent_backup_receipt_health(
  candidate_organization_id uuid
)
returns table(
  checked_receipts bigint,
  backup_receipts bigint,
  restore_receipts bigint,
  manifest_hash_mismatches bigint,
  manifest_canonical_mismatches bigint,
  manifest_schema_mismatches bigint,
  manifest_binding_mismatches bigint,
  key_binding_mismatches bigint,
  latest_backup_age_seconds numeric
)
language plpgsql
stable
security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare
  receipt record;
  manifest jsonb;
  source_receipt public.backup_receipts%rowtype;
  latest_backup_snapshot timestamptz;
  expected_recovery jsonb;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker'
     or candidate_organization_id is null
     or not public.boardagent_is_uuid_v7(candidate_organization_id) then
    raise exception 'backup receipt health scope or organization is invalid'
      using errcode='22023';
  end if;
  if not exists (
    select 1 from public.system_instance as instance
     where instance.singleton_key
       and instance.organization_id=candidate_organization_id
  ) then
    raise exception 'backup receipt health organization is unavailable' using errcode='42501';
  end if;

  checked_receipts := 0;
  backup_receipts := 0;
  restore_receipts := 0;
  manifest_hash_mismatches := 0;
  manifest_canonical_mismatches := 0;
  manifest_schema_mismatches := 0;
  manifest_binding_mismatches := 0;
  key_binding_mismatches := 0;

  for receipt in
    select value.*
      from public.backup_receipts as value
     where value.organization_id=candidate_organization_id
     order by value.created_at,value.id
  loop
    checked_receipts := checked_receipts+1;
    if receipt.receipt_kind='backup' then
      backup_receipts := backup_receipts+1;
      latest_backup_snapshot := greatest(
        coalesce(latest_backup_snapshot,'-infinity'::timestamptz),receipt.snapshot_at
      );
    elsif receipt.receipt_kind='restore' then
      restore_receipts := restore_receipts+1;
    else
      manifest_schema_mismatches := manifest_schema_mismatches+1;
    end if;

    if receipt.manifest_sha256<>pg_catalog.sha256(receipt.canonical_manifest) then
      manifest_hash_mismatches := manifest_hash_mismatches+1;
    end if;

    begin
      manifest := convert_from(receipt.canonical_manifest,'UTF8')::jsonb;
      if jsonb_typeof(manifest)<>'object' then
        raise data_exception;
      end if;
    exception when others then
      manifest_canonical_mismatches := manifest_canonical_mismatches+1;
      manifest_schema_mismatches := manifest_schema_mismatches+1;
      continue;
    end;

    if not (manifest ?& array[
      'schemaVersion','receiptKind','receiptId','instanceId','organizationId',
      'snapshotLsn','snapshotAt','contentSetSha256','encryptionKeyId'
    ]) then
      manifest_schema_mismatches := manifest_schema_mismatches+1;
    end if;

    if manifest->>'receiptId'<>receipt.id::text
       or manifest->>'organizationId'<>receipt.organization_id::text
       or manifest->>'snapshotLsn'<>receipt.snapshot_lsn::text
       or manifest->>'snapshotAt'<>to_char(
         receipt.snapshot_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
       )
       or manifest->>'contentSetSha256'<>encode(receipt.content_set_sha256,'hex')
       or manifest->>'encryptionKeyId'<>receipt.encryption_key_id::text then
      manifest_binding_mismatches := manifest_binding_mismatches+1;
    end if;

    if receipt.receipt_kind='backup' then
      if receipt.schema_version not in ('boardagent.backup-receipt.v1','boardagent.backup-receipt.v2')
         or receipt.source_backup_receipt_id is not null
         or receipt.state<>'created'
         or receipt.verified_restore_at is not null
         or manifest->>'schemaVersion' is distinct from receipt.schema_version
         or manifest->>'receiptKind'<>'backup' then
        manifest_schema_mismatches := manifest_schema_mismatches+1;
      end if;
    elsif receipt.receipt_kind='restore' then
      source_receipt := null;
      select source.* into source_receipt
        from public.backup_receipts as source
       where source.id=receipt.source_backup_receipt_id;
      if receipt.schema_version not in ('boardagent.restore-receipt.v1','boardagent.restore-receipt.v2')
         or receipt.source_backup_receipt_id is null
         or receipt.state<>'verified'
         or receipt.verified_restore_at is null
         or manifest->>'schemaVersion' is distinct from receipt.schema_version
         or manifest->>'receiptKind'<>'restore' then
        manifest_schema_mismatches := manifest_schema_mismatches+1;
      end if;
      if source_receipt.id is null
         or source_receipt.receipt_kind<>'backup'
         or source_receipt.organization_id<>receipt.organization_id
         or manifest->>'sourceBackupReceiptId'<>source_receipt.id::text
         or manifest->>'sourceBackupManifestSha256'<>encode(source_receipt.manifest_sha256,'hex')
         or manifest->>'verifiedAt'<>to_char(
           receipt.verified_restore_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
         )
         or receipt.snapshot_lsn<>source_receipt.snapshot_lsn
         or receipt.snapshot_at<>source_receipt.snapshot_at
         or receipt.content_set_sha256<>source_receipt.content_set_sha256
         or receipt.encryption_key_id<>source_receipt.encryption_key_id then
        manifest_binding_mismatches := manifest_binding_mismatches+1;
      end if;
    end if;

    begin
      if receipt.receipt_kind='backup' then
        if coalesce(manifest#>>'{auditBoundary,eventCount}','') !~ '^(0|[1-9][0-9]{0,18})$' then
          raise data_exception;
        end if;
        expected_recovery:=public.boardagent_recovery_evidence_at_head(
          receipt.organization_id,(manifest#>>'{auditBoundary,eventCount}')::bigint
        );
      else
        expected_recovery:=coalesce(
          convert_from(source_receipt.canonical_manifest,'UTF8')::jsonb->'auditRecoveryEvidence','[]'::jsonb
        );
      end if;
      if (expected_recovery='[]'::jsonb and (
            receipt.schema_version not in ('boardagent.backup-receipt.v1','boardagent.restore-receipt.v1')
            or manifest ? 'auditRecoveryEvidence'))
         or (expected_recovery<>'[]'::jsonb and (
            receipt.schema_version not in ('boardagent.backup-receipt.v2','boardagent.restore-receipt.v2')
            or manifest->'auditRecoveryEvidence' is distinct from expected_recovery)) then
        manifest_binding_mismatches:=manifest_binding_mismatches+1;
      end if;
    exception when others then
      manifest_schema_mismatches:=manifest_schema_mismatches+1;
    end;

    if not exists (
      select 1
        from public.crypto_key_registry as key
       where key.id=receipt.encryption_key_id
         and key.organization_id=receipt.organization_id
         and key.purpose='backup_kek'
         and key.algorithm='A256GCM'
         and key.public_jwk is null
         and key.activated_at<=receipt.snapshot_at
         and (key.retired_at is null or key.retired_at>receipt.snapshot_at)
         and (key.compromised_at is null or key.compromised_at>receipt.snapshot_at)
    ) then
      key_binding_mismatches := key_binding_mismatches+1;
    end if;
  end loop;

  latest_backup_age_seconds := case when latest_backup_snapshot is null then null else
    extract(epoch from transaction_timestamp()-latest_backup_snapshot) end;
  return next;
end
$$;

alter function public.boardagent_backup_receipt_health(uuid)
  owner to boardagent_migrator;
revoke all on function public.boardagent_backup_receipt_health(uuid)
  from public;
grant execute on function public.boardagent_backup_receipt_health(uuid)
  to boardagent_worker;
