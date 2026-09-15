-- BoardAgent Phase 4 / group 82: read-only worker inspection of immutable backup
-- and restore receipt evidence. Only content-safe aggregate health leaves the
-- security-definer boundary; raw manifests, storage locators and receipt IDs do not.

create function public.boardagent_backup_receipt_health(
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
set search_path=pg_catalog,public
as $$
declare
  receipt record;
  manifest jsonb;
  source_receipt public.backup_receipts%rowtype;
  latest_backup_snapshot timestamptz;
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
      if receipt.schema_version<>'boardagent.backup-receipt.v1'
         or receipt.source_backup_receipt_id is not null
         or receipt.state<>'created'
         or receipt.verified_restore_at is not null
         or manifest->>'schemaVersion'<>'boardagent.backup-receipt.v1'
         or manifest->>'receiptKind'<>'backup' then
        manifest_schema_mismatches := manifest_schema_mismatches+1;
      end if;
    elsif receipt.receipt_kind='restore' then
      source_receipt := null;
      select source.* into source_receipt
        from public.backup_receipts as source
       where source.id=receipt.source_backup_receipt_id;
      if receipt.schema_version<>'boardagent.restore-receipt.v1'
         or receipt.source_backup_receipt_id is null
         or receipt.state<>'verified'
         or receipt.verified_restore_at is null
         or manifest->>'schemaVersion'<>'boardagent.restore-receipt.v1'
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
