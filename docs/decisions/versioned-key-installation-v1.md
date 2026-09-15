# Versioned private-key installation — 9 September 2026

Under the delegated completion instruction, `key-lifecycle install INSTALL.json` completes
the filesystem stage of the existing technical-operator command family. It grants no
company administrator, secretary, director, agent or runtime database role new authority.
The frozen proposal and operational registry pins remain historical and unchanged; the
command-family/event counts do not change. This is the additive install-mode contract.

This mode requires production configuration, Linux host-root and the actual migrator
principal. The operator wrapper holds the existing exclusive kernel maintenance lock.
The installer holds the SQL0137 exclusive transaction lock while reading the committed
operation, validating materials and preparing files. Database work is read-only. The
referenced operation's replacement must still be the current active key. Every purpose
must have exactly one active uncompromised key; a standalone retirement or compromise
must be followed by replacement before a complete running generation can be installed.

The strict `boardagent.key-generation-plan.v1` file contains operationId, requestSha256,
a new absolute generationRoot, keyFiles[{keyId,file}], retainedDataKeyIds and passwordFiles
for the migrator/server/worker/backup principals. Inputs are bounded physical protected
files. Only active keys and keys actually needed by retained runtime dependencies are
loaded. Each is matched to its actual registered purpose, algorithm, kid, public material
or backup fingerprint. A second bounded read must match the validated file fingerprint.
All four database passwords must be distinct and authenticate their actual target logins.
The original password/key files are never changed.

Active/locked TOTP and active webhook records determine required retained data keys.
The declared list must match. Retained keys must be retired and uncompromised. Server
receives keys needed for TOTP/webhooks; worker receives only webhook dependencies. The
manifest binds IDs, kids, full fingerprints, instance and organization. A manifest above
1 MiB refuses before installation. Key/plan input bounds preserve the existing 4096-key
ceiling; this is not an unqualified throughput claim.

The installer exclusively creates a new root-owned private generation directory. Each
role directory is root:10001 mode 0750; service files are 10001:10001 mode 0400. Server gets
its four active purposes and own database password. Worker gets evidence/data and its own
password. The privileged operator also gets backup material and the backup/worker passwords
needed by existing backup/receipt commands. Recovery gets only backup key/password/receipt.
An actual current-registry backup receipt is generated. Existing source paths, directories,
volumes, retired keys, ciphertext and public verification history are preserved.

Every destination and file/directory collision is validated before output. Each new key
parent carries an incomplete marker while files are written and fsynced, including ownership
metadata. The deployment override and completed generation manifest are published last.
Existing or partial generation directories refuse; the operator preserves them and selects
a new empty destination. Database commit and filesystem publication are not claimed to be
one atomic operation. Interruption can leave a preserved partial generation and requires
inspection. No command silently deletes it, reuses it or claims a running service.

The generated override is for the same production + recovery Compose project. It mounts
only each role's directory read-only, requires existing host directories and preserves the
same maintenance coordination volume. It removes original secret initializers from runtime
and PostgreSQL dependencies and excludes those initializers from ordinary startup. Existing
PostgreSQL data/password volumes remain in use. Runtime locators must be inside the supported
secret mount; fixed reserved names and prefix collisions refuse. Dollar signs in generated
YAML data are escaped against Compose interpolation. Merge behavior is checked with the
actual Compose engine and follows [Docker's merge specification](https://docs.docker.com/reference/compose-file/merge/).

A `generation_prepared` result means files/configuration are ready for controlled restart.
It explicitly reports `restart_and_verify_required`; it is not readiness, deployment,
human login or off-host custody evidence. Keep the operation receipt, private installation
plan, generation manifest, selected Compose files and actual restart/recovery results.
No Docker socket or automatic service start is given to the installer.

SR-028/068/082, TH-40 map to scripts/src/key-generation-install.ts, the existing key-lifecycle
operator and kernel wrapper. tests/operations/key-generation-install.spec.ts exercises real
Linux root installation, authority/file/digest failures, role-isolated mounts, preserved
source material, generated Compose dependencies and production server/worker restart.
Retained-generation restores, complete/native qualification and independent review remain
separate requirements; no pass is asserted by this decision document alone.
