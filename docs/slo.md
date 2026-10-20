# Service level objectives (O3) — definitions and measurement

**Status:** recorded 2026-10-20 (WP02). Targets fixed by the contract. Measurement
implementation: WP09. Rows O2–O4 are **Not demonstrated** until measured over the
qualification window in a production-identical environment.

| ID | Objective | Target | Numerator / denominator | Clock start → stop | Exclusions |
|---|---|---|---|---|---|
| SLO-1 | Core application availability (monthly) | 99.9% | minutes in which the synthetic core-workflow probe (login → brief → propose → approve in sandbox tenant → kernel accepts) succeeds / minutes in month | per probe run | none; a provider outage that breaks the workflow counts against availability |
| SLO-2 | Non-AI API latency | p95 ≤ 500 ms, p99 ≤ 1.5 s | all authenticated non-AI requests | request received at ALB → last byte | draft generation, exports |
| SLO-3 | Daily brief retrieval | p95 ≤ 2 s | GET brief requests | same | — |
| SLO-4 | Draft generation | p95 ≤ 15 s with visible progress and cancel | draft requests | request → draft ready | cancelled requests reported separately |
| SLO-5 | Approved eligible action → dispatch start | p95 ≤ 10 s, p99 ≤ 60 s | actions whose approval consumed and `queued` while policy permits immediate dispatch | approval commit → `dispatch_authorized` | actions scheduled in the future; valid policy denials (reported separately, never dropped) |
| SLO-6 | Authenticated inbound persistence | p99 ≤ 2 s | authenticated webhook events | provider request received → durable commit before ack | authentication failures (alerted, not latency) |
| SLO-7 | Inbound received → inbox visible | p95 ≤ 5 s | authenticated inbound events | provider timestamp → visible in inbox API | — |
| SLO-8 | Explicit opt-out recorded → new dispatch blocked | immediate at the authorization boundary | opt-outs | suppression commit → next dispatch-authorization attempt observes it | in-flight provider submissions (documented non-retractable) |
| SLO-9 | Recovery point objective | ≤ 5 min | — | last committed transaction → restore point | — |
| SLO-10 | Recovery time objective | ≤ 60 min | — | incident declared → core workflow available with dispatch disabled per O9 | — |

## Capacity envelope (O2)

1,000 consultant businesses; ≤10 users each; 1,000,000 customer records; 100 read rps;
20 write/proposal rps; 10 dispatch/s subject to provider limits. Per-tenant limits prevent
noisy-tenant exhaustion; above-capacity work is rejected gracefully (429 with retry
guidance). Limits published internally.

## Load programme (O4)

8 h at envelope; 30 min at 2×; 24 h at ½ for leaks; provider simulator for volume (no bulk
real messages). Pass: SLOs met at envelope; 0 unauthorized/duplicate execution; no
unbounded queue growth; no unexplained resource growth; graceful limiting above
capacity; normal service ≤10 min after overload ends.

## Reporting

Each SLO is reported with numerator, denominator, window, and the exclusion counts
(scheduled, denied) shown separately. Error budget burn alerts feed O7.
