-- BoardAgent Phase 1 / group 33: immutable backup and isolated-restore receipts.

alter table crypto_key_registry
  drop constraint crypto_key_registry_purpose_check,
  add constraint crypto_key_registry_purpose_check check (
    purpose in ('oauth_signing', 'evidence_signing', 'browser_session', 'data_kek', 'backup_kek')
  );

alter table backup_receipts
  drop constraint backup_receipts_schema_version_check,
  drop constraint backup_receipts_check,
  add column receipt_kind text not null default 'backup'
    check (receipt_kind in ('backup','restore')),
  add column source_backup_receipt_id uuid references backup_receipts(id) on delete restrict,
  add constraint backup_receipts_schema_version_check check (
    schema_version in ('boardagent.backup-receipt.v1','boardagent.restore-receipt.v1')
  ),
  add constraint backup_receipts_kind_state_check check (
    (receipt_kind='backup' and schema_version='boardagent.backup-receipt.v1'
      and state in ('created','failed') and source_backup_receipt_id is null)
    or
    (receipt_kind='restore' and schema_version='boardagent.restore-receipt.v1'
      and state in ('verified','failed') and source_backup_receipt_id is not null)
  ),
  add constraint backup_receipts_verified_restore_check check (
    (receipt_kind='restore' and state='verified' and verified_restore_at is not null)
    or (state<>'verified' and verified_restore_at is null)
  );

grant insert on backup_receipts to boardagent_worker;
grant select on backup_receipts to boardagent_migrator;
create policy boardagent_migrator_backup_receipt_read on backup_receipts
  for select to boardagent_migrator using (true);

create function boardagent_guard_backup_receipt_insert()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  manifest jsonb;
  instance_row system_instance%rowtype;
  encryption_key crypto_key_registry%rowtype;
  source_receipt backup_receipts%rowtype;
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
    if manifest->>'schemaVersion'<>'boardagent.backup-receipt.v1'
       or manifest->>'receiptKind'<>'backup' then
      raise exception 'backup receipt manifest fields differ from the evidence row'
        using errcode = '23514';
    end if;
  else
    select * into strict source_receipt from backup_receipts where id=new.source_backup_receipt_id;
    if source_receipt.receipt_kind<>'backup'
       or source_receipt.organization_id<>new.organization_id
       or manifest->>'schemaVersion'<>'boardagent.restore-receipt.v1'
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
  return new;
end;
$$;
alter function boardagent_guard_backup_receipt_insert() owner to boardagent_migrator;
revoke all on function boardagent_guard_backup_receipt_insert() from public;
create trigger boardagent_backup_receipt_insert_guard
  before insert on backup_receipts
  for each row execute function boardagent_guard_backup_receipt_insert();

create trigger boardagent_immutable
  before update or delete on backup_receipts
  for each row execute function boardagent_reject_evidence_mutation();
revoke update, delete on backup_receipts from boardagent_server, boardagent_worker;

create function boardagent_backup_receipt_lookup(candidate_receipt_id uuid)
returns table(
  receipt_kind text,
  manifest_sha256 bytea,
  source_backup_receipt_id uuid
)
language plpgsql
stable
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'worker' then
    raise exception 'backup receipt lookup requires a managed worker transaction'
      using errcode = '25000';
  end if;
  return query
    select receipt.receipt_kind,receipt.manifest_sha256,receipt.source_backup_receipt_id
      from backup_receipts as receipt where receipt.id=candidate_receipt_id;
end;
$$;
alter function boardagent_backup_receipt_lookup(uuid) owner to boardagent_migrator;
revoke all on function boardagent_backup_receipt_lookup(uuid) from public;
grant execute on function boardagent_backup_receipt_lookup(uuid) to boardagent_worker;
