# 21 — Retention and soft deletion

**Owners:** organization admin/secretariat for governed lifecycle; deployment owner for
temporary operational storage. **Purpose:** apply visible lifecycle and bounded ephemera
cleanup without claiming erasure that v1 cannot perform.

1. Read `get_retention_policy` and identify the record class: governance/content/audit/
   consent/evidence versus temporary export, expired stage/challenge/session, notification,
   lease, or other operational ephemera.
2. For a supported governance lifecycle action, use the exact archive/cancel/soft-delete
   tool and complete confirmation where required. Verify ordinary visibility, historical
   lineage, audit evidence, and authorized recovery/correction behavior.
3. For worker-managed ephemera, inspect age, state, retention threshold, references, and
   worker health; allow only the typed cleanup job. Verify it cannot target protected
   governance/content/audit/consent/evidence rows.
4. For encrypted export artifacts, confirm external custody and authorization before
   `delete_export_artifact`.

BoardAgent v1 has **no physical purge** for governance, content, audit, consent, or evidence.
Soft deletion is not privacy erasure, media destruction, or key destruction. Never issue
direct SQL/file deletion to simulate a feature. A legal erasure/conflict request must be
escalated to counsel, the project owner and the security owner for a separately reviewed process.

Record record class/ID, authority, lifecycle before/after, confirmation/audit receipt,
cleanup-job evidence, remaining retained lineage, and the exact statement made to the
requester about non-erasure.
