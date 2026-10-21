# Competitive verification — study protocol and analysis (contract K1, WP11)

**Status: Implemented (protocol + analysis tool). K1 is Not demonstrated; no
participant has been recruited, no alternative has been selected, no session
has run.** Until K1 passes, no market-superiority wording may appear anywhere
(contract: "Production readiness and market leadership are separate
conclusions"). This document contains no comparative claim.

## Design (fixed by the contract)

* **Comparators:** (a) the participating consultants' current official-tool
  workflow; (b) two independently available alternatives with the strongest
  *verified* overlap in follow-up, reminders, customer messaging and task
  management. The verification owner selects (b) through documented current
  feature/access checks recorded in `selection.md` (date, URL, feature table,
  trial account evidence). Convenience is not a criterion.
* **Participants:** 12 independent consultants; inclusion/exclusion criteria
  recorded before recruitment; compensation identical across arms.
* **Crossover:** every participant performs the 20 matched scenarios on every
  arm; arm order randomized per participant (`tools/qualification/k1_analysis.py randomize --seed …`
  prints the Latin-square order and is committed before sessions start).
  Matched scenarios differ only in surface detail (names, dates, products).
* **Scenarios (20 per participant, ≥ 1 of each):** promise capture; daily
  prioritization; follow-up preparation; approval; reply deferral; opt-out;
  product concern; uncertain delivery; outcome recording; finding the reason
  behind an action.
* **Measures per scenario per arm:** active handling time (s, from scenario
  start to the participant's declared completion, pauses excluded), correct
  completion (binary, scored by two raters blind to arm against a pre-written
  rubric; disagreements adjudicated and logged), privacy/opt-out/approval
  behaviour violations (count), post-arm preference (forced choice among arms
  for the follow-through workflow, with free-text reason).

## Acceptance (verbatim)

≥ 30 % lower **median** active handling time on the predefined follow-through
task set than the **best** tested alternative; ≥ 95 % correct task completion;
no degradation in opt-out, approval or privacy behaviour; ≥ 10 of 12
participants prefer MK for the tested follow-through workflow; all methods,
exclusions and results retained. If targets fail: improve the product and
repeat the study. A pass supports **only the tested claim**.

## Data files (never committed with participant identities)

`sessions.csv`: `participant,arm,scenario,order,handling_time_s,correct,violations,rater_a,rater_b`
`preferences.csv`: `participant,preferred_arm,reason`

## Analysis

```sh
python -I tools/qualification/k1_analysis.py analyze sessions.csv preferences.csv
```

Exit 0 only when every acceptance condition holds. Output JSON is the
`actual_result` for `evidence/releases/<id>/K1.yaml`; the claims register
(`docs/release/claims-register.md`) may then carry exactly the sentence the
tool prints under `supported_claim`, and nothing broader.
