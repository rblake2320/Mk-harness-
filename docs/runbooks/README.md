# Runbooks (O7, O9, O10)

Operational procedures required by the completion contract. Each runbook is exercised
in a game day before release; the record of the exercise is evidence under
`evidence/releases/<id>/`.

| Runbook | Covers | Status |
|---|---|---|
| `../../deploy/kernel/README.md` §Production runbook | bring-up, pre-flight, enable sequence, stop/rollback, key rotation | written; not exercised |
| `restore-without-resend.md` | O9: restore with dispatch disabled → verify chain → load suppression/deletion ledger → reconcile vs provider → mark unknown → invalidate pre-restore approvals → confirm credentials → release-owner authorization | to write (WP09) |
| `incident-unapproved-or-duplicate-send.md` | immediate dispatch shutdown, evidence capture, customer remediation | to write (WP09) |
| `inbound-outage.md` | 60 s pause behaviour, recovery checks, backlog processing | to write (WP07/09) |
| `key-compromise.md` | containment for provider, assertion, DB, KMS keys | to write (WP09) |
