# ADR 0005: Canonical shared record, agent-owned derived memory

- Status: accepted at Gate 2 and clarified during implementation
- Date: 2026-09-05
- Authority: D2-001, D2-018, D2-019, D2-025, D2-028, D2-029, D2-045, SR-024, SR-025

## Context

BoardAgent is used by directors, observers, management, and the secretariat through their
own agents. Agents benefit from presentation preferences and recollection, but a shared
mutable semantic “brain” would create a second, less accountable source of governance
truth.

If the deployment operator, management, or another privileged contributor could rewrite
shared memory, they could bias what all agents recall without amending the underlying
record. A central memory index could also leak the existence or meaning of recused and
confidential matters across principals, retain a stale interpretation after a correction,
collapse disputed viewpoints into one summary, or make generated text appear to have board
authority. A compromised client-side agent can likewise alter its own memory, so derived
memory cannot be trusted merely because it is local.

## Decision

BoardAgent has no Open Brain, vector database, embedding service, semantic memory, or
server-side AI. It holds the common authoritative layer only: canonical versioned records,
identity and authority, lifecycle state, immutable history, audit/checkpoint evidence,
snapshots, update cursors, pending actions, and tombstones.

Each person or AI observer may allow their own client/agent to keep derived local memory.
That memory:

1. remains outside BoardAgent and inside that principal's client trust boundary;
2. is private by default and is never automatically synchronized between agents;
3. must retain the source URI/object, version, canonical hash, and retrieval time;
4. must be refetched before a binding act or other material reliance;
5. must apply authority changes, recusal/confidentiality exclusions, corrections, and
   tombstones;
6. must be labeled as derived presentation rather than a BoardAgent record; and
7. is never accepted by BoardAgent as identity, authority, evidence, consent, a vote, or a
   substitute for exact canonical input.

The human remains responsible for reviewing presentation and exact confirmation. An AI
observer's accountable-principal metadata remains part of every server-side record; its
private memory never expands the observer's authority.

## Security and governance consequences

- Management cannot create a globally preferred narrative by editing a shared semantic
  store. It can contribute only through attributed, governed records and immutable threads.
- A director's preferences and derived notes do not become visible to management or other
  board participants through BoardAgent.
- Recusal and confidentiality remain server-enforced on every fetch; client caches are a
  residual risk disclosed during onboarding and must process tombstones.
- Different agents may produce different summaries. That is acceptable because only the
  cited canonical record has governance significance.
- BoardAgent cannot prove that a client deleted or correctly updated local memory. A
  compromised client can still mislead its own user, which is why binding acts refetch and
  use server-attested exact confirmation.
- No server memory means BoardAgent does not offer semantic recall, personalization across
  clients, cross-agent knowledge synthesis, or automated conflict detection.

## Rejected alternatives

### One organization-wide semantic brain

Rejected because its writers, ranking, update semantics, ACL/recusal behavior, and generated
interpretations would become a hidden governance authority and a cross-principal disclosure
surface.

### One server-hosted private memory namespace per member

Rejected for v1 because BoardAgent would still become responsible for semantic generation,
retention, deletion, model/provider behavior, and proof that confidential derivations never
cross namespaces. The benefit does not justify that new trust boundary.

### No agent memory at all

Rejected as unenforceable and unnecessarily restrictive. Clients can keep local state; the
safe contract is to make its derived/non-authoritative status explicit and refuse to trust
it on the server.

## Future change boundary

Any shared or server-hosted semantic memory is a substantive new capability requiring a
fresh architect cycle. At minimum it must define and test authorship, per-principal and
per-object ACLs, live recusal, provenance, versioning, challenge/correction, tombstones,
retention/erasure, prompt-injection quarantine, provider/model/eval drift, encryption,
operator access, exports, incident response, and explicit human control. It must not be
activated as a cache, optional plug-in, or dormant provider under the v1 release.

## Verification expectations

The existing v1 net proves absence of server AI/embedding/vector dependencies, uniform
recusal/confidentiality across fetch surfaces, snapshot/delta/tombstone behavior, and fresh
canonical confirmation. Client-side memory hygiene remains a documented client obligation
and an independent-client review item rather than a server claim.
