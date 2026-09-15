# 13 — Minutes, redlines, and signatures

**Owner:** secretariat; members/observers act only on their own review/signature. **Purpose:**
move minutes through immutable drafting, review, disposition, signature, finalization, and
correction.

1. Read meeting, attendance, agenda, source documents, transcript/Q&A annex, and existing
   minutes lineage. Run `record-minutes` or use `create_minutes_version` for canonical text.
2. Use `log_minutes_action_items` with a structured owner/due/evidence manifest, or
   `declare_no_minutes_action_items`. Do not hide actions in prose only.
3. `publish_minutes` opens the exact version for review. Members/observers use
   `comment_minutes`, `withdraw_minutes_comment`, or `propose_minutes_redline`; redlines are
   anchored strict JSON, never binary tracked changes.
4. The secretariat reads `list_minutes_review_items` and uses
   `resolve_minutes_review_item` with an explicit disposition. Material changes require
   `correct_minutes_package` and a fresh published version; do not edit under reviewers.
5. After all review items and action structure are settled, use
   `prepare_minutes_for_signature`. Each entitled person independently calls
   `stage_minutes_signature` and completes the server confirmation over the exact package.
6. Use `finalize_minutes` only when the configured signature/evidence requirements are
   satisfied. Verify hashes, signer set, and linked actions.
7. For a finalized error, use `create_minutes_correction_cycle`; never rewrite signed
   history. Cancel only through `cancel_minutes` under its lifecycle rules.

Record every version/package hash, review item and disposition, action manifest, signature
receipt, finalization, lineage, correction reason, and superseded pending action. An
observer signature is record attestation, not a vote.
