# 15 — Rulesets and governance profile

**Owners:** admin/secretariat under the frozen authority matrix. **Purpose:** activate typed,
cited governance rules without allowing client prose or an evaluator to become authority.

1. Read `get_board_governance_profile`, `get_ruleset`, `list_ruleset_versions`, the board's
   canonical charter source, and `list_approval_rule_templates`/`list_matter_types`.
2. Run `configure-ruleset` or assemble the strict typed draft. Every threshold, quorum,
   electorate rule, proxy rule, approval rule, exception, and override path needs a source
   citation and unambiguous precedence.
3. Call `validate_ruleset_draft`. Resolve every error; validation is deterministic and does
   not activate the draft.
4. Use `evaluate_matter` on boundary examples and hand-check results against the cited
   source. It records reproducible facts but does not provide legal advice.
5. Use `manage_ruleset` or `configure_board_governance` as required and complete exact
   human confirmation. Record activation time and version/hash.
6. Rerun boundary evaluations and inspect any open vote/draft that referenced an earlier
   version. Existing packages remain bound to their recorded version; do not silently
   transplant new rules.

Refuse ambiguous citations, unsupported free-form executable logic, contradictory
precedence, or an attempt to grant authority outside the central policy. Record source
hashes/citations, validation output, boundary fixtures, confirmation receipt, active
version, and affected-work review.

Preserve that record as the activation evidence for the exact ruleset version.
