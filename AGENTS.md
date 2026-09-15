# BoardAgent contributor contract

Read `BUILD_PLAN.md` before changing this repository. The approved design decisions,
authority matrix, verification net, manifests and approval records under `planning/`
are byte-frozen: do not edit them or reinterpret a decision. Changes to a frozen
decision are recorded additively under `docs/decisions/` and approved by the project
owner.

Work only inside this repository. Do not use real board data, and do not weaken a
verification threshold or skip a failing check to obtain a green result. Every security
claim needs a requirement row in `docs/VERIFICATION.md` with an exact implementation
pointer and an exact executing test. Skipped, unavailable, quarantined and unexecuted
are not passes. There is no server-side AI, format conversion, extraction, SMTP,
governance web UI or physical governance-record purge in v1.

Write the failing test first. Run `tests/run_all.py` before and after a change; only
the project owner blesses a changed regression baseline with `tests/bless.py --yes`.
Regenerate `docs/SURFACE_REFERENCE.md` and the generated registry through
`scripts/src/generate-registry.ts` rather than editing them by hand.
