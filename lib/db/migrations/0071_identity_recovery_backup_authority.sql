-- BoardAgent Phase 4 / group 71: restore complete backup visibility for the
-- identity-recovery aggregate introduced after the original role/RLS sweep.

grant select on public.identity_recovery_requests to boardagent_backup;

create policy boardagent_backup_read
  on public.identity_recovery_requests for select to boardagent_backup
  using (true);
