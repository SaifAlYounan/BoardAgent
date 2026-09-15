# Operational completion instruction — 8 September 2026

This record restates, in formal terms, a project-owner instruction originally given
privately. Original SHA-256:
efa2618e9b22a2b61fa8be13a28c24acdff7f043b308012f7d97f10ba82c58ce. The project owner
approved this restatement on 16 September 2026.

After explanations of audit capacity, missed-checkpoint recovery and operator key rotation,
the project owner instructed the builder to make every operational procedure easy for
people to fix, auditable and secure; to document everything so that it can be understood
by reading the manual; and to finish the build.

The builder treats this as direction to choose, implement, test and document the internal
engineering needed for those outcomes. The builder must not repeat the earlier approval
loop or require the owner to select internal event limits. This is delegated
implementation judgment; it is not a claim that the project owner approved every detail of
earlier drafts or selected the proposed one-million-event transaction ceiling.

Preserve original frozen planning, proposal snapshots, historical decisions and migrations.
Record each revised technical decision additively, with implementation and executed proof.
Keep ordinary checkpoint segments at most 1,000 events with their 15-minute deadline. Any
increased atomic-action allowance must be explicit, bounded and justified by supported
workloads; signing debt must restrict further work until caught up. A missed deadline can
be recovered only through a controlled operator procedure with permanent truthful findings.
No backdating, rewriting history, granting agent or operator shortcuts, or silent cap
removal. Key replacement belongs to the technical operator and must preserve historical
evidence and required decryption keys, with actual restart and restore tests.

Every manual procedure must identify the responsible role, prerequisites, exact supported
steps, expected output, safe failure and retry path, and retained audit evidence. Clearly
label unfinished commands; operators must not improvise SQL or silently delete failed work.
Reviews by an AI coding agent remain bounded, and optional comments do not create an
endless rewrite loop. Whole-source and native qualification precede the already authorized
repaired synthetic deployment. Personal enrollment, client trials, real operational custody
and website acceptance still require actual people and inputs; they must not be
manufactured. This instruction changes no running service by itself and claims no
qualification pass.
