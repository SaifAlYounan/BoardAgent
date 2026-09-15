-- Runtime connections can own temporary objects. A fixed path that omits pg_temp
-- still searches that namespace first for relations/types, including PL/pgSQL
-- declarations compiled on a fresh backend. Pin it explicitly last in every
-- BoardAgent helper, including invoker helpers called by privileged finalizers.
-- No owner, EXECUTE grant, role, table policy or action authority is changed.
do $$
declare
  routine record;
begin
  for routine in
    select p.proname,pg_catalog.pg_get_function_identity_arguments(p.oid) as arguments
      from pg_catalog.pg_proc p
      join pg_catalog.pg_namespace n on n.oid=p.pronamespace
      where n.nspname='public' and left(p.proname,11)='boardagent_'
        and p.prokind='f'
      order by p.proname,p.oid
  loop
    execute pg_catalog.format('alter function public.%I(%s) set search_path=pg_catalog,public,pg_temp',
      routine.proname,routine.arguments);
  end loop;
end
$$;
