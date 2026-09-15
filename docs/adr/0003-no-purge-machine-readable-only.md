# ADR 0003: Permanent records and machine-readable-only materials

- Status: accepted at Gate 2
- Date: 2026-08-28
- Authority: D2-023 through D2-027 and D2-049

## Decision

BoardAgent v1 accepts only UTF-8 Markdown, UTF-8 plain text and versioned strict JSON.
PDF, PowerPoint, Word, images, scans and archives are rejected before durable storage,
including when offered as evidence. Rejection is loud and states that no rejected bytes
were retained. There is no converter, extractor, OCR engine, model provider, dormant
provider configuration or outbound content-check implementation.

Accepted system-of-record materials, governance actions and their immutable histories
are retained indefinitely. “Delete” is visibility-only and creates permanent snapshots
and tombstones. Named ephemeral authentication/session artifacts may expire; governance
records cannot be physically purged.

## Future boundary

A versioned provider interface/schema namespace may be documented for a future external
preflight gate, but no executable adapter, key, network permission or fallback ships in
v1. Activating one is a substantive capability change requiring the full architect
lifecycle and a new threat/evaluation net.
