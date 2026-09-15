-- Record the exact granted scope set on each refresh family so an access token that was
-- narrowed to onboarding:read before the person attested current onboarding can widen
-- back to the granted set on a later refresh. Existing families keep a NULL column and
-- continue to use their prior access token's scope set; no historical row changes.
alter table public.refresh_families
  add column granted_scope_set text[]
    check (granted_scope_set is null or cardinality(granted_scope_set) between 1 and 128);
