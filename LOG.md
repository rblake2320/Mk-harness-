# Engineering Log

This is the chronological evidence index. `CHANGELOG.md` describes release
behavior, `WHY.md` records decisions, and `PARKED.md` preserves deferred or
removed ideas with restoration conditions.

## 2026-07-10 - Governed phone-agent work orders

- **Implementation:** [`8af28b7`](https://github.com/rblake2320/Mk-harness-/commit/8af28b71425c5b15aa4a6f73c463b22c97cd87dd)
- **Privacy follow-up:** [`fde98ec`](https://github.com/rblake2320/Mk-harness-/commit/fde98ecaaa890a5d22a76d8c7cc54aca232f040d)
- **Branch:** `agent/call-center-phoneclaw-harness`
- **Actor:** Codex, at the repository owner's request
- **Scope:** call-center models, queue, dispatcher, adapter envelope, signed
  transport/callbacks, contact permissions, audit chain, API routes, tests,
  dependency refresh, and v1.7.0 version synchronization
- **Decisions:** [WHY.md](WHY.md)
- **Deferred/restorable work:** [PARKED.md](PARKED.md)
- **Release summary:** [CHANGELOG.md](CHANGELOG.md#170--2026-07-10)

### Verification evidence

| Check | Result | Boundary |
|---|---|---|
| Repo-local `pytest -q` | 131 passed, 1 skipped | Redis durability test skipped because `redis-server` was not installed locally |
| `pytest tests/test_call_center.py -q` | 8 passed | HTTP-simulated adapter/provider boundaries; no real phone |
| `ruff check app tests` | Passed | Static lint only |
| `ruff format --check` on new call-center files | Passed | New files only; legacy tree was not mechanically reformatted |
| `pip-audit -r requirements.txt` | No known vulnerabilities found | Advisory database result on 2026-07-10, not a future guarantee |
| `npm ci` | 0 audit findings | npm advisory result on 2026-07-10 |
| `npm run build` | Passed | TypeScript plus Vite production build |
| PhoneClaw upstream review | ClawScript helper API found; no HTTP/webhook contract found | Reviewed `rohanarun/phoneclaw` main at `c59995b` |
| Real-device execution | Not performed | `verified_on_device` remains `false` |

### Rollback

Revert `fde98ecaaa890a5d22a76d8c7cc54aca232f040d` first, then
`8af28b71425c5b15aa4a6f73c463b22c97cd87dd`, to reverse the feature without
rewriting history. Review database tables and retained work orders before
deploying a rollback; reverting code does not delete data.
