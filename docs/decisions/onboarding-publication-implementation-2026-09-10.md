# Supported onboarding publication — 10 September 2026

This record restates, in formal terms, a project-owner instruction originally given
privately. Original SHA-256:
707c35c86c0219393935a1dbc18020ff65f90f6e4126d5988f65b103eb72dbd4. The project owner
approved this restatement on 16 September 2026.

Basis: source finding BA-E2E-0031 and the supported-surface failing tests
R5-onboarding-publication-before (both handlers missing). Design assistance from an AI
coding agent was completed on an unchanged isolated source; no release approval was
given. SQL0002 originally keyed attestations only by terms; the current SQL0053 already
includes `support_version_id`. An initially proposed duplicate correction failed
migration; SQL0053 is retained unchanged and the existing support-only reattestation
path is tested.

D2-028 explicitly assigns versioned support contacts to the secretary. Terms are existing
organization-wide, role-specific records; the frozen design specifies acceptance but does
not name a publisher. Under the project owner's instruction to choose a secure, auditable
and understandable implementation and to finish, the builder selects the company
administrator with S:A as publisher. This is an explicit gap-filling interpretation, not
a claim that the frozen matrix named this tool or that a reviewer granted authority. No
board secretary receives organization-wide terms powers. Original planning,
administrative and operational amendments remain byte-frozen.

Add two H tools: `publish_secretary_support` (current active board secretary + S:A, board
required, no organization-default publication) and `publish_onboarding_terms` (current
human company administrator + S:A, role-specific organization scope). The exact proposed
version ID, the expected preceding version ID (null only if absent), the canonical
content and the reason bind the confirmation. All updates take effect immediately; all
terms changes are treated as material, and support changes also require fresh personal
acceptance. Existing records and attestations are immutable. The new registry amendment
is pinned additively; no threshold or original policy is edited.

The database finalizer consumes same-transaction protected-response consent, the exact
current snapshot and matching audit. Runtime roles get no direct publication writes.
Existing version uniqueness and an organization lock order competing publications; stale
or mismatched approval is refused. Scope, role, current onboarding, non-observer status
and recusal are checked in SQL. Publication runs after audit so that it may invalidate
the publisher's prior onboarding without skipping evidence. No new passkey, consent or
attestation is issued on anyone's behalf. The existing SQL0053 uniqueness on (member,
board, terms, support) allows separate personal support-only reacceptance. All old rows
are preserved.

The project owner's instruction was to make everything easy for people to fix, auditable,
secure and documented so that it can be understood from the manual, and to finish the
build; a later instruction authorized bounded assistance from an AI coding agent and
completion. The builder interprets that instruction to resolve this unspecified publisher
responsibility within the existing company-administrator role. This document records the
interpretation; it is not an explicit approval of every field.

## Initial support on a newly created board

A supported `create_board` creates no support version and no implicit seat. Requiring
current board onboarding before the first support publication would form a dependency
cycle; a failing real create-board-then-publish test confirms this omission. The same
company administrator who bootstraps the organization may therefore publish a board's
first support version under current admin + S:A authority, before enrollment. This is
explicit setup responsibility under delegated completion judgment. The exception requires
no existing board support version, an active same-organization board, current human admin
eligibility and no board recusal. It creates no membership, grants no future
support-update power, and cannot replace an existing version. Subsequent publication
remains the responsibility of the current board secretary. The same protected
confirmation, audit and version-locking rules apply. The administrator's own
administrative stage and audit policies admit only this actor's corresponding setup
evidence; no hidden board-record reads are added.

The expected prior version is optional input: omitting it makes the server capture the
current version and hash in the exact protected snapshot; a supplied value still asserts
that preceding ID. A stale confirmation cannot follow a new publication in either mode.
