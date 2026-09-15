# Retained data keys — runtime implementation decision

Recorded 9 September 2026 under the actual
[operational completion instruction](operational-completion-instruction-2026-09-08.md).
This implements a prerequisite of F7. It does not assert approval of the old proposal,
change frozen authority, implement a key transition or document a completed custody ceremony.

Production may supply `BOARDAGENT_RETAINED_DATA_KEYS_FILE`, a distinct absolute manifest
path. Development/test profiles refuse that configuration. The active data key remains in
its existing purpose-separated file and alone encrypts new TOTP/webhook/export material.
An absent manifest preserves the existing one-key configuration. Historical keys are loaded
only from explicit file references, never by scanning an archive or accepting inline bytes.

The strict `boardagent.retained-data-keys.v1` manifest contains instanceId, organizationId
and keys. Each entry contains keyId, kid, fingerprintSha256 and an absolute normalized
keyFile path. It is bounded to 1 MiB and 4096 entries; whichever limit is reached first applies.
Duplicate JSON names, unknown fields and repeated IDs/kids/fingerprints/paths are refused.
The limits bound startup work and memory; they are not a limit on archived key history.

Each opened file is checked through its descriptor: a regular single-link file owned by
root or the process user, no world access, execution bits or group write. Explicit group
read is allowed for existing production custody mounts. Final symlinks, hardlinks and
nonregular files are refused. Input reads are bounded before parsing and changes to the
opened file during reading refuse. Existing incomplete-initialization markers still block
startup. Retained symmetric material is 32 raw bytes or 43 canonical base64url characters,
optionally followed by one LF; the reader caps it at 44 bytes. Parse/file diagnostics never
include supplied private values. Partial retained buffers are cleared on failure.

The full SHA-256 fingerprint is checked against actual loaded bytes, and the existing
version 1 data kid is independently derived from those bytes. Startup through the server
and worker capability roles binds the manifest to the actual configured instance/org and
each registry UUID/kid/purpose/algorithm. Only activated, ordinarily retired, uncompromised
data keys with no public-JWK field qualify as historical runtime material. A key still
active, retired in the future, absent or compromised is refused. Existing registry data
kids are 96-bit derived identifiers; this prerequisite does not claim an independently
registered full fingerprint for legacy rows. The manifest supplies its full fingerprint.

Both compositions supply the checked old/current key map to decryption consumers. New
webhook material still uses the active key. TOTP authentication retains its live compromise
check; pending enrollment retains the existing active-key requirement. The worker receives
no OAuth or browser key through this feature. No key identity or ciphertext row is rewritten.

Executing evidence is in unit/retained-data-keys.test.ts and
integration/retained-data-keys.postgres.test.ts, plus affected configuration, initialization,
application/worker runtime, key-validity and TOTP tests. Fixture retirement creates controlled
history; it is explicitly not an operator rotation or a person's real enrollment.

Still required in F7: protected prepare/apply/inspect; complete database/filesystem dependency
inventory; enforcement that a transition cannot omit required old material; pending-TOTP
handling through supported authority; webhook rewrap and ordinary management continuity;
live stale-process refusal; all five purposes; actual pre/post-transition encrypted restores
and final qualification/review. Startup currently checks explicitly listed retained keys;
it does not discover every encrypted dependency or prove that an omitted archive key exists.
