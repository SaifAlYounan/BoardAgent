import type { JsonValue } from "../../lib/contracts/src/canonical.js";
import { ORIGINAL_GOVERNANCE_LIST_SQL } from "./governance-lists-original-sql.js";
type Kind = "rulesets" | "templates" | "matter_types";
export const governanceListOriginalKeys = {
  rulesets: [
    "ruleset_id",
    "version",
    "state",
    "schema_version",
    "sha256",
    "profile_id",
    "supersedes_id",
    "created_at"
  ],
  templates: ["template_id", "code", "approval_rule_id", "exact_rule", "sha256"],
  matter_types: ["matter_type_id", "code", "name", "strict_fact_schema", "sha256"]
} as const;
const idKey = {
  rulesets: "ruleset_id",
  templates: "template_id",
  matter_types: "matter_type_id"
} as const;
const jsonKey = {
  rulesets: null,
  templates: "exact_rule",
  matter_types: "strict_fact_schema"
} as const;
const hash = (v: string) => `encode(sha256(convert_to((${v})::text,'UTF8')),'hex')`;
const utf8 = (v: string) => `coalesce(octet_length(convert_to((${v})::text,'UTF8')),0)::numeric`;
// Deliberately starts with the complete captured ORIGINAL result. This oracle
// runs before occupancy/fault controls; it is not the admitted implementation.
export function governanceListOriginalMetadataSQL(kind: Kind): string {
  const jk = jsonKey[kind],
    fields = governanceListOriginalKeys[kind];
  const flat = fields.filter((key) => key !== jk).map((key) => `v.item->>'${key}'`);
  const privateFields = fields.map((key) =>
    key === jk
      ? hash(`v.item->'${key}'`)
      : key === "name"
        ? hash("v.item->>'name'")
        : `v.item->'${key}'`
  );
  const raw =
    kind === "rulesets"
      ? "(select ruleset_source.created_at::text from rulesets as ruleset_source where ruleset_source.id=(v.item->>'ruleset_id')::uuid)"
      : "v.cursor_at";
  return `with recursive original as (${ORIGINAL_GOVERNANCE_LIST_SQL[kind]}),
    source as materialized (select v.*,v.item->>'${idKey[kind]}' as id,${raw} as raw_order_key,
      ${jk ? `v.item->'${jk}'` : "null::jsonb"} as arbitrary from original as v),
    nodes(id,value,member) as (
      select id,arbitrary,false from source where arbitrary is not null union all
      select n.id,child.value,child.member from nodes as n cross join lateral (
        select value,true as member from jsonb_each(case when jsonb_typeof(n.value)='object' then n.value else '{}'::jsonb end)
        union all select value,false as member from jsonb_array_elements(case when jsonb_typeof(n.value)='array' then n.value else '[]'::jsonb end)
      ) as child
    ), metrics as (
      select id,(count(*) filter(where member))::text as json_property_count,
        (count(*) filter(where jsonb_typeof(value) in ('object','array')))::text as json_container_count
      from nodes group by id
    )
    select v.id,v.cursor_at,v.raw_order_key,
      ${hash(`jsonb_build_array(${privateFields.join(",")},v.raw_order_key)`)} as observation_sha256,
      (${[...flat, "v.cursor_at", "v.cursor_id"].map(utf8).join("+")})::text as scalar_utf8,
      ${utf8("v.arbitrary")}::text as normalized_json_utf8,
      coalesce(m.json_property_count,'0') as json_property_count,
      coalesce(m.json_container_count,'0') as json_container_count
    from source as v left join metrics as m on m.id=v.id
    order by ${kind === "rulesets" ? "v.raw_order_key::timestamptz desc,v.id::uuid desc" : "v.raw_order_key,v.id::uuid"}`;
}
export function governanceListOriginalGraph(value: JsonValue) {
  let properties = 0,
    containers = 0;
  const pending = [value];
  while (pending.length) {
    const v = pending.pop();
    if (v === null || typeof v !== "object") continue;
    containers++;
    if (!Array.isArray(v)) properties += Object.keys(v).length;
    pending.push(...Object.values(v));
  }
  return { properties, containers };
}
