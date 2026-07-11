# Engineering Log

This is the chronological evidence index. `CHANGELOG.md` describes release
behavior, `WHY.md` records decisions, and `PARKED.md` preserves deferred or
removed ideas with restoration conditions.

## 2026-07-10 - Governed Mobile Workflows

- **Implementation:** [`8af28b7`](https://github.com/rblake2320/Mk-harness-/commit/8af28b71425c5b15aa4a6f73c463b22c97cd87dd)
- **Privacy follow-up:** [`fde98ec`](https://github.com/rblake2320/Mk-harness-/commit/fde98ecaaa890a5d22a76d8c7cc54aca232f040d)
- **Environment gate:** [`0a03142`](https://github.com/rblake2320/Mk-harness-/commit/0a03142e970e5b21b142ca3e6129e8e8328c5b53)
- **Naming, suppression, migrations:** [`1888499`](https://github.com/rblake2320/Mk-harness-/commit/188849924b3db5d21f79d9bc2b756af83971705f)
- **Branch:** `agent/call-center-phoneclaw-harness`
- **Actor:** Codex, at the repository owner's request
- **Scope:** Agent Operations models, queue, dispatcher, adapter envelope, signed
  transport/callbacks, contact permissions, audit chain, API routes, tests,
  dependency refresh, and v1.7.0 version synchronization
- **Decisions:** [WHY.md](WHY.md)
- **Deferred/restorable work:** [PARKED.md](PARKED.md)
- **Release summary:** [CHANGELOG.md](CHANGELOG.md#170--2026-07-10)

### Verification evidence

| Check | Result | Boundary |
|---|---|---|
| Repo-local `pytest -q` | 135 passed, 1 skipped | Redis durability test skipped because `redis-server` was not installed locally |
| `pytest tests/test_agent_ops.py -q` | 10 passed | HTTP-simulated adapter/provider boundaries; no real phone |
| `pytest tests/test_migrations.py -q` | 2 passed | Fresh SQLite chain and stamped v1.6.2 upgrade path |
| `ruff check app tests` | Passed | Static lint only |
| `ruff format --check` on new Agent Operations files | Passed | New files only; legacy tree was not mechanically reformatted |
| `pip-audit -r requirements.txt` | No known vulnerabilities found | Advisory database result on 2026-07-10, not a future guarantee |
| `npm ci` | 0 audit findings | npm advisory result on 2026-07-10 |
| `npm run build` | Passed | TypeScript plus Vite production build |
| Local Docker/PostgreSQL | Not run | Docker Desktop Linux engine was unavailable; GitHub CI owns this check |
| PhoneClaw upstream review | ClawScript helper API found; no HTTP/webhook contract found | Reviewed `rohanarun/phoneclaw` main at `c59995b` |
| Real-device execution | Not performed | `verified_on_device` remains `false` |

### Tracked production gates

- [#21 device-token lifecycle](https://github.com/rblake2320/Mk-harness-/issues/21)
- [#22 durable queue](https://github.com/rblake2320/Mk-harness-/issues/22)
- [#23 stale-task recovery](https://github.com/rblake2320/Mk-harness-/issues/23)
- [#24 PII redaction and retention](https://github.com/rblake2320/Mk-harness-/issues/24)
- [#25 schema and adapter simulator](https://github.com/rblake2320/Mk-harness-/issues/25)
- [#26 opt-out/suppression synchronization](https://github.com/rblake2320/Mk-harness-/issues/26)
- [#27 signed receipts and external anchoring](https://github.com/rblake2320/Mk-harness-/issues/27)

### Rollback

For an application-only rollback, revert `1888499`, `0a03142`, `fde98ec`, then
`8af28b7` without rewriting history; the unused tables remain. A schema rollback
to `0001` deletes Agent Operations tables and their data, so export evidence,
take a verified backup, and obtain explicit approval before running it.
