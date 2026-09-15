# BoardAgent operator runbooks

Start with the [plain-language manual](../MANUAL.md) to identify the responsible person
and the procedure for the problem you see.

These runbooks cover the frozen single-VPS private-beta profile. They are procedures, not
authorization. Replace examples only with exact deployment values, keep secrets out of
shell history and receipts, and never use real board data before Gate 3 approval.

## Universal rules

Before any procedure, record the operator, authority, start time, target deployment,
source/image digest, current readiness, and change/incident reference. Use an independent
observer for key, recovery, release, and destructive host-level ceremonies.

Stop and escalate when:

- the target, identity, board, image, key, backup, or authority is ambiguous;
- source or image digests differ from the approved manifest;
- an expected one-use receipt is missing, malformed, replayed unexpectedly, or partial;
- readiness, audit, backup, clock, or worker health is already degraded without explanation;
- a command would overwrite a nonempty restore target or erase governance evidence;
- the requested action depends on a feature outside the frozen v1 profile.

Every completed runbook produces a receipt containing what was requested, what actually
happened, canonical non-secret identifiers/hashes, verification performed, exceptions,
and the next owner. “Command exited” is not sufficient evidence.

## Index

1. [Runtime, TLS, readiness, and drain](01-runtime-tls-readiness-drain.md)
2. [Bootstrap](02-bootstrap.md)
3. [Members and AI observers](03-members-and-ai-observers.md)
4. [Identity recovery](04-identity-recovery.md)
5. [OIDC and UAE Pass assessment](05-oidc-and-uae-pass.md)
6. [Client registration and allowlisting](06-client-registration.md)
7. [Token or client incident](07-token-client-incident.md)
8. [Key rotation and compromise](08-key-rotation-compromise.md)
9. [Documents and content rejection](09-documents-content-rejection.md)
10. [Recusal and confidentiality](10-recusal-confidentiality.md)
11. [Meetings and attendance](11-meetings-attendance.md)
12. [Transcripts and Q&A](12-transcripts-qna.md)
13. [Minutes, redlines, and signatures](13-minutes-redlines-signatures.md)
14. [Votes, proxies, and certificates](14-votes-proxies-certificates.md)
15. [Rulesets and governance profile](15-rulesets-governance-profile.md)
16. [Tasks, proposals, and management workflow](16-tasks-proposals-management.md)
17. [Worker and jobs](17-worker-jobs.md)
18. [Webhooks](18-webhooks.md)
19. [Audit, certificate, and export verification](19-audit-certificate-export-verification.md)
20. [System export](20-system-export.md)
21. [Retention and soft deletion](21-retention-soft-delete.md)
22. [Backup, PITR, and restore](22-backup-pitr-restore.md)
23. [Migrations, upgrade, and rollback](23-migrations-upgrade-rollback.md)
24. [Outage and capacity](24-outage-capacity.md)
25. [MCP upgrade and client compatibility](25-mcp-upgrade-compatibility.md)
26. [Incident response](26-incident-response.md)
27. [Release candidate and Gate 3](27-release-candidate-gate3.md)
28. [Periodic controls](28-periodic-controls.md)
29. [Recover after an audit-signing interruption](29-audit-signing-recovery.md)
30. [Update onboarding terms and secretary support](30-onboarding-terms-and-support.md)
31. [Renew an expired first administrator invitation](31-expired-first-invitation.md)
32. [Restart a pending activation](32-activation-restart.md)
33. [Persistent local installation for acceptance](33-local-persistent-install.md)

## Escalation

- Governance records/access: secretariat.
- Runtime, DNS/TLS, database, secrets, backup: deployment administrator.
- Suspected compromise: security contact.
- Product policy or release acceptance: product owner. The Architect workflow is retired.
