# Runbooks (O7, O9, O10)

Operational procedures required by the completion contract. Each runbook is exercised
in a game day before release; the record of the exercise is evidence under
`evidence/releases/<id>/`.

| Runbook | Covers | Status |
|---|---|---|
| `../../deploy/kernel/README.md` §Production runbook | bring-up, pre-flight, enable sequence, stop/rollback, envelope key rotation (`mk-keyctl`) | written; rotation exercised by smoke gate 11 (author-run → Implemented) |
| `restore-without-resend.md` | O9: restore with dispatch disabled → verify chain → load suppression/deletion ledger → reconcile vs provider → mark unknown → invalidate pre-restore approvals → confirm credentials → release-owner authorization. Tooling: `mk-restore-gate`; drill F6 | written (Implemented); timed drill against a real snapshot not performed |
| `incident-unapproved-or-duplicate-send.md` | immediate dispatch shutdown, evidence capture, classification table, customer remediation, re-enable, postmortem | written (Implemented); game day not performed |
| `inbound-outage.md` | 60 s stale/pause behaviour (`inbound_dispatch_block`), signed replay of missed inbound, backlog processing, strict resume | written (Implemented); game day not performed |
| `key-compromise.md` | containment per key class (provider token, assertion key, passkey, DB logins, master key, KEK, JWT); verification after rotation; known gap on master-key re-fingerprinting | written (Implemented); exercises not performed |
