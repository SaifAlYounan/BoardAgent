# Offline recovery across backup-key generations — 9 September 2026

The delegated completion instruction requires retained backups to remain usable after
key replacement. The prior offline PITR command accepted one key for the base and every
WAL file, so it could not replay across a backup-key replacement. The actual encrypted
two-generation failing case is `tests/unit/wal-key-generations.test.ts`.

`BOARDAGENT_BACKUP_RECOVERY_KEYS_FILE` is an optional private operator input to the
existing `prepare-pitr` command. It names a strict, bounded
`boardagent.backup-recovery-keys.v1` JSON file containing one instance/organization and
key IDs, physical private-file paths and expected full fingerprints. The selected base
key must be listed and match the explicitly configured base key. IDs, paths and key
fingerprints cannot repeat. The 4,096-entry/1 MiB bound follows the existing key-registry
limit; no maximum-size performance qualification is implied.

`scripts/src/recovery-keyring.ts` uses the existing opened-inode protected file reader
and actual backup material parser. The entire supplied keyring is validated before use.
`scripts/src/wal-archive.ts` checks every manifest's exact key selection and fingerprint
and common target before any plaintext segment output; there is no implicit fallback
to a different key. Ordinary single-key recovery remains compatible. Existing legacy
manifest warnings are preserved, and actual authenticated decryption is still required.
`scripts/src/pitr.ts` retains the keyring digest and actual selected key IDs in the
preparation receipt. Preparation is not a running or verified database.

This input authorizes no online writer, registers no key, changes no database permission,
and does not give historical backup keys to server/worker containers. Offline recovery
deliberately works without the original database. The custodian must preserve trustworthy
key/receipt records; archive metadata cannot independently establish custody or trust.
Memory buffers are cleared when finished, without claiming perfect JavaScript erasure.

SR-028/068/082 and TH-40: implementation paths are named above and operator.ts. The unit
test rejects missing, duplicate, foreign-target and mismatched key lists before plaintext
output. `tests/operations/wal-base-backup.spec.ts` applies an actual database key replacement,
starts the new WAL writer, produces base backups on both sides and starts two actual
PostgreSQL recoveries through old/new encrypted WAL. `tests/operations/recovered-audit-backup.spec.ts`
restores old and new encrypted logical databases after replacement and compares the exact
audit rows, preserving prior recovery findings. Exact executing tests belong in
docs/VERIFICATION.md; this decision alone is not a qualification or deployment pass.

## Bounded review follow-up: interrupted published-file replay

The same optional list is accepted by `archive-wal-once` solely to authenticate an
already published prior-generation pair before acknowledging its staged source. Current
registry validation and kernel exclusion still authorize the writer; old keys never
choose encryption for new files. `validatePublishedWal` still authenticates decryption,
compares staged plaintext and verifies artifact/manifest hashes and sizes. The prior
manifest's key is selected explicitly and its recorded installation must match the current
receipt. The output records prior-generation replay count and the keyring digest.
Continuous writers do not automatically receive or load historical keys.

`tests/unit/wal-key-generations.test.ts` exercises the existing operator command with a
real encrypted prior-generation pair and rejects missing key sets, a foreign installation,
tampered ciphertext even with a matching updated public hash, and mismatched staged bytes.
Success preserves archived bytes; a subsequent normal pass writes new WAL under the
current key without the historical key list. This repairs the bounded review's reproducible
replay deadlock while retaining the stronger authentication requirement.
