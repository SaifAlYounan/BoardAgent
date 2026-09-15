# 09 — Documents and content rejection

**Owners:** submitting member/management and secretariat. **Purpose:** admit only reviewed,
canonical machine-readable material and preserve immutable versions.

## Accept a document

1. Establish the authoritative source owner, title, board, confidentiality/access set,
   purpose, and supported media/schema version.
2. If the original is PDF, Word, PowerPoint, image, scan, archive, or other unsupported
   binary, an accountable person creates and reviews canonical Markdown/text/declared JSON
   outside BoardAgent. Do not upload the original or claim BoardAgent converted it.
3. Use `create_document_version` with the exact content. Read back `get_document_hash` and
   `read_document`; compare length/hash and material text with the reviewed input.
4. For management material, use `submit_document_to_secretariat` and its immutable revision
   thread. For circulation, run the `circulate-document` prompt and complete
   `circulate_document` confirmation over exact recipients/version.
5. Verify list/search/direct-read visibility for an entitled person and denial for an
   excluded/recused synthetic principal.

## Choosing a format

Use UTF-8 Markdown or plain text for a charter, resolution, report, or other ordinary
document. Supply `schema_name: null`, NFC text and LF line endings. The exact maximum
is 10 MiB for both submitted and canonical content. An agent can help convert a source
outside BoardAgent; the submitting person must check that conversion.

JSON requires one of these compiled, versioned formats. A made-up schema label is refused,
even if it looks like a BoardAgent version name. Required fields and types are checked;
extra fields, mismatched `schemaVersion`, duplicate keys and unknown versions are refused.

| `schema_name`                   | Required content                                                                                                                                  |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `boardagent.board-pack.v1`      | `schemaVersion`, `title`, and one or more `sections`, each with `heading` and `body` strings.                                                     |
| `boardagent.minutes-comment.v1` | The strict comment format: minutes ID, base version/hash, comment and citations.                                                                  |
| `boardagent.minutes-redline.v1` | The strict redline format: minutes ID, base version/hash, exact anchor and anchored-text hash, operation, proposed text, rationale and citations. |

A minimal board pack is:

```json
{
  "schemaVersion": "boardagent.board-pack.v1",
  "title": "Exploration programme",
  "sections": [{ "heading": "Resolution", "body": "Approve the proposed exploration programme." }]
}
```

Board-pack titles and headings are limited to 512 characters, with 1–1,000 sections;
the overall byte limit still applies. The exact minutes formats are defined by
`MinutesCommentSchema` and `MinutesRedlineSchema` in
[`lib/contracts/src/governance.ts`](../../lib/contracts/src/governance.ts).
Uploading a comment or redline as a document stores content only. Use `comment_minutes`
or `propose_minutes_redline` to apply the corresponding review workflow and its authority checks.

If validation fails, use the displayed reason and validation-attempt reference to correct
the source, or use reviewed Markdown/plain text. Rejected document bytes are not retained.
Adding a JSON format requires a versioned schema, tests and a reviewed software release;
an administrator cannot bypass validation by registering a label or providing a URL.
Previously stored records and their hashes remain permanent and unchanged.

## Rejection

On unsupported media, invalid Unicode, oversized input, unknown schema, external URL,
executable/active content, malformed canonical form, or ambiguous source ownership, fail
loudly. Identify the rejected class and ask the accountable submitter for a reviewed
machine-readable replacement. Do not OCR, scrape, unzip, render, or silently normalize it.

New versions never overwrite prior versions. Archive and `soft_delete_document` change
lifecycle/visibility but do not physically purge content or evidence. Record input hash,
created version/hash, validation result, access manifest, circulation receipt, and any
rejection reason.
