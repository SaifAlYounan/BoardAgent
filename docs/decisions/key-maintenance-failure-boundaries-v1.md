# Key maintenance during signing failure — 9 September 2026

An AI-assisted review of the source at that time reported two reproducible maintenance gaps:
ordinary signing-debt admission could roll back lost-key containment, and initial
registrars could create an unaudited successor after a standalone retirement.

Additive SQL0138 preserves all earlier migration bytes. The capacity trigger admits only
the current operator transaction's exact next-sequence `key_lifecycle_changed` receipt:
matching operation/entity/organization/details/time, actual xid and server incarnation,
bootstrap scope and absent person/client/board/consent fields. SQL0131's applied-effect
validation and deferred mandatory completion remain in force. This exception does not
establish ordinary transaction admission. Governance remains blocked at full debt;
checkpoint and any overdue-recovery duties, history and incident findings remain intact.

Initial registration still serializes on the existing per-purpose lock and supports
exact active-key replay. If no active key exists but any historical key of that purpose
exists, both registrars refuse a successor. The audited lifecycle is the only supported
successor procedure. The trusted infrastructure operator remains privileged; this guards
supported commands against accidental bypass, not a claim that database ownership is inert.

Regression: `tests/integration/key-lifecycle-operator.postgres.test.ts` fills actual signing
debt, removes the evidence private file, records compromise and replacement, checks unchanged
history/no invented checkpoints and rejects ordinary appends both between operations and
inside the same operation transaction. It retires each of the five purposes through the
CLI and verifies the initial registrars refuse successors without new rows. Initial runtime
and backup registration/replay, forged and missing lifecycle evidence, atomic capacity and
upgrade-at-full-backlog tests also execute. The initial runtime fixture incorrectly supplied
one registration instead of the required four; corrected failing-first evidence is retained
separately and demonstrates six actual behavioral failures before SQL0138.

The operator surfaces `audit_signing_backlog` distinctly rather than suggesting another
identical preparation. Runbook 08 provides the incident and initial-registration steps.
This closes no native, human or whole-release gate by itself.
