# BoardAgent roadmap

These are the next changes, in the order that unblocks users. Today a person can read
their board from any MCP client, but a binding act (a vote, an invitation, a governance
change) can only be confirmed from a client that renders MCP elicitation forms. That is
the first thing to change.

## 1. Binding acts confirmed in the browser with a passkey

A vote, an invitation or a governance change is confirmed through an MCP elicitation
form. Clients that do not render forms are refused. Replace the typed-code form with the
pattern onboarding already uses: the agent stages the act, the server mints a one-time
link, the person opens it on any device, reads the exact resolution and signs with their
passkey. Every client then works, the proof is a WebAuthn signature instead of an
eight-character code, and the ten-minute code windows disappear. Keep the elicitation
path as a fallback where a client supports it.

## 2. Administrator step-up that always asks for the passkey

`confirm_enrollment_activation`, `reissue_activation`, `change_seat` and governance
changes need a browser authentication within ten minutes, but re-authorising through a
browser that still holds the site session silently reuses it and refreshes nothing.
Force a passkey assertion on step-up and show the remaining step-up time in `whoami`.

## 3. Enrollment page: make the proofing choice explicit and echo it back

The person picks "In person" or "Verified number call" on the enrollment page. The
administrator's confirmation and any restart must pass exactly that value, and a
mismatch is refused with a generic message. Show the chosen method next to the reference
and the code so the person reads all three to the administrator, and name the mismatch
in the refusal shown to the administrator.

## 4. WAL archive range filter in recovery

`materializeWalArchive` decrypts every archived segment, so a restore rehearsal on a
long-running instance cannot finish inside its budget on a small host. Decrypt only the
segments from the base backup's start LSN onward, and let the archiver retire segments
older than the oldest retained base backup.

## 5. Performance harness

The 100-way burst's pool acquire wait is 60 seconds and the burst has no latency target.
Decide whether it should have one, and record the host class it is measured on.

## 6. Client packaging

A director's setup should be one link, not a manual `claude mcp add` plus two sign-ins.
Ship a connector manifest per role and a one-page "join your board" flow.
