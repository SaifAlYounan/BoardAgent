// Exact pre-admission lineage SELECT; test-only, no runtime fallback.
export const ORIGINAL_MINUTES_LINEAGE_SQL = `select coalesce(jsonb_agg(jsonb_build_object(
           'correction_cycle_id',cycle.id,'original_minutes_id',cycle.original_minutes_id,
           'replacement_minutes_id',cycle.replacement_minutes_id,'reason',cycle.reason,
           'secretary_member_id',cycle.secretary_member_id,
           'created_at',to_char(cycle.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
         ) order by cycle.created_at,cycle.id),'[]'::jsonb) as items
         from minutes_correction_cycles as cycle
        where cycle.original_minutes_id=$1 or cycle.replacement_minutes_id=$1`;
