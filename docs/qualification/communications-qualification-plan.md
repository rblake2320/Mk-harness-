# Real communications qualification — plan and tally (contract C10, WP11)

**Status: Implemented (plan + tally tool). C10 is Not demonstrated until the
30-day window has run with a registered production sender and the tally
passes on retained provider receipts AND receiving-device corroboration.**

## Requirement (verbatim targets)

1 000 approved controlled messages over 30 consecutive days, ≥ 6 receiving
test numbers across ≥ 3 mobile networks; all traffic permitted and sent to
controlled recipients. Acceptance: zero unapproved messages; zero duplicate
customer messages; ≥ 99 % of eligible messages corroborated on the receiving
device within 5 minutes; ≥ 99.5 % reach provider acceptance or an explicit
visible failure within 60 s; every ambiguous submission surfaced and reconciled
or explicitly left unknown; opt-out, wrong-number, failure and recovery
scenarios included; no unresolved sev-1/sev-2 incident in the window; failed
actions never count as successes; provider receipts and device corroboration
retained as **distinct** evidence.

## Preconditions (none may be assumed)

* Legal/provider decision M1 recorded; sender registered (10DLC or equivalent)
  under the consultant business; `docs/legal-review.md` updated.
* Production topology deployed (D5/O1) with `MK_TWILIO_API_BASE=https://api.twilio.com`,
  `mk_provider_live == 1`, dispatch enabled through the passkey step-up.
* Six prepaid test handsets on three carriers, each with consent recorded as a
  real customer would (web form proof digests), owned by the qualification
  team; their numbers listed in `recipients.csv` (never committed).

## Daily procedure (≈ 34 messages/day)

| Scenario (contract) | Share | How |
|---|---|---|
| normal approved follow-up | 70 % | drafts proposed by the agent principal, approved by a human approver with a real passkey |
| opt-out | 5 % | handset replies STOP; the next proposal to it must be `403 suppressed`; re-consent later via form |
| wrong number | 5 % | a recipient replies "wrong number"; held for meaning; consultant resolves; no further send |
| failure | 10 % | an invalid/unroutable test number (carrier-provided) → explicit visible failure within 60 s |
| recovery | 10 % | one planned worker restart and one planned Redis flush per week during sends (`docs/runbooks/`) |

Every message gets one row in `messages.csv` (schema below). The handset
corroboration is a timestamped screenshot or the device's SMS database export
hashed and stored under `evidence/releases/<id>/c10/device/`; provider
receipts are the `message_deliveries` + `delivery_events` export for the day
under `.../c10/provider/`. The two are never derived from each other.

## `messages.csv` schema

```
action_id,approved_at,approval_credential_id,provider_message_id,provider_state,provider_state_at,
device_number,device_seen_at,scenario,expected,duplicate_of,ambiguous_resolution,incident_id
```

* `expected` ∈ `delivered | failed | suppressed | held`
* `provider_state` is the contract vocabulary (`docs/production-acceptance.md` C3)
* `device_seen_at` empty = not corroborated; `duplicate_of` non-empty = the same customer message arrived twice
* `ambiguous_resolution` ∈ `reconciled_sent | reconciled_not_sent | left_unknown | ""`

## Tally

```sh
python -I tools/qualification/c10_tally.py messages.csv --window 2026-11-01..2026-11-30
```

Exit 0 only if every acceptance condition holds; the JSON it prints becomes
`actual_result` in `evidence/releases/<id>/C10.yaml`. The tool's own tests:
`python -m unittest tools/qualification/test_c10_tally.py`.
