# 14 — Votes, proxies, and certificates

**Owners:** secretariat for vote lifecycle; each voting member for their ballot/proxy;
deployment/security owner for offline trust distribution.

**Purpose:** create, change, act on, close, and independently verify a vote without carrying
authority or assent across changed canonical content.

## Prepare and open

1. Read the board governance profile, active ruleset/citations, member/electorate state,
   recusals, documents, approved management submission, and included Q&A cutoffs.
2. Use `evaluate_matter` as a reproducible typed aid, not legal advice. Run `set-vote` to
   build the exact decision package and validate any explicit override reason.
3. Complete `create_vote` confirmation. Verify resolution text, package hash, eligible set,
   rule/profile versions, deadline, notice work, and open state.

## Act and change

1. A member reads `get_vote`, sources, `get_proxy_status`, and live authority immediately
   before `stage_ballot`, then personally completes confirmation.
2. Use `grant_proxy`/`revoke_proxy` only for the exact scope/period; verify precedence and
   that neither act creates a second counted ballot.
3. A resolution/source/electorate change uses `amend_resolution_text`,
   `replace_open_vote`, or the explicit pending-source exclusion path. Never mutate the
   package under existing confirmations. Notify and require revote as specified.
4. `extend_vote_deadline` and `cancel_vote` require exact reason and confirmation.

## Close and verify

1. Verify deadline/closure authority, no unresolved included Q&A or pending source,
   electorate/recusal/proxy state, quorum, ballots, rule, and any override.
2. Complete `close_vote`. The worker recovery path may finish certificate issuance after a
   crash but must not recompute a different outcome.
3. Read `get_vote_certificate` and verify authenticated consistency. Export the bundle and
   trusted public key set for independent offline verification:

   ```sh
   node scripts/dist/operator.js verify-certificate BUNDLE.json TRUSTED_KEYS.json
   ```

4. Public verification accepts only opaque `public_id` or a bounded bundle and returns a
   generic validity result. It is not a source for protected vote detail.

## Evidence

Record package/electorate/rule hashes, ballot/proxy receipts, replacements/notices, close
outcome, certificate/signing key/issuance time, verification result, and trust-set digest.
