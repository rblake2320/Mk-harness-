#!/usr/bin/env bash
# Live end-to-end smoke of the governed path THROUGH THE APPLICATION:
#
#   FastAPI /api/agent-ops  ─assertion─▶  mk-action-api  ─outbox─▶ relay ─▶ redis ─▶ worker
#        ▲                                                                       │ HMAC work order
#        │ app JWT                                                               ▼
#      curl                                     tools/mobile-agent-adb (MK_EXECUTOR=dry-run)
#                                                                               │ signed callbacks
#                                                                               ▼
#                                                              mk-action-api  → audit chain → verifier
#
# Proves, with real processes and a real Postgres/Redis:
#   1. an approved action reaches the device agent and its callback is accepted;
#   2. a *suppressed* contact is refused at proposal (403, nothing queued);
#   3. a *revoked* approval is not dispatched (action not Dispatching/Completed);
#   4. the tenant kill switch blocks dispatch of an approved action;
#   5. the same proposal twice yields one action (idempotent), the same
#      assertion twice yields 401 (shared jti);
#   6. the audit chain verifies at the end.
#
# Requires: cargo (RUSTUP_TOOLCHAIN=stable), python3 with backend deps, psql,
# a Postgres at $PGURL and Redis at $REDIS_URL. Nothing here touches a phone:
# the agent runs in dry-run and reports `failed/dry_run_no_device`, which is
# the honest terminal state. Run with MK_EXECUTOR=adb and a device attached to
# produce real-device evidence (see docs/real-device-acceptance.md).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-$(mktemp -d)}"
PGURL="${PGURL:-postgres://postgres:kernel@127.0.0.1:5433/mk_kernel_smoke}"
REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6380}"
API=http://127.0.0.1:8090
APP=http://127.0.0.1:8000
AGENT=http://127.0.0.1:8787
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}"
log() { printf '\033[1;36m[smoke]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[smoke FAIL]\033[0m %s\n' "$*"; exit 1; }
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

log "building release binaries"
(cd "$ROOT/rust" && cargo build --release -q --bin mk-action-api --bin mk-outbox-relay \
   --bin mk-action-worker --bin mk-audit-verifier --bin mk-devkeys)
BIN="$ROOT/rust/target/release"

log "fresh database"
psql "${PGURL%/*}/postgres" -qc "DROP DATABASE IF EXISTS ${PGURL##*/}" -c "CREATE DATABASE ${PGURL##*/}"
redis-cli -u "$REDIS_URL" FLUSHALL >/dev/null

eval "$("$BIN/mk-devkeys" gen)"      # MK_ASSERTION_KEYS, DEV_PRIVATE_KEY, MK_MASTER_KEY
export MK_ASSERTION_KEYS MK_MASTER_KEY
export MK_DATABASE_URL="$PGURL" MK_REDIS_URL="$REDIS_URL" RUST_LOG=info
MK_MIGRATE_ONLY=1 "$BIN/mk-action-api" >/dev/null

# Deployment enforcement: every process type gets its own LOGIN identity that
# inherits exactly one privilege role (deploy/kernel/roles.sql). RLS is then
# enforced for real — the admin URL above is used only for migrations.
log "creating per-process database identities"
PW=smoke-$(python3 -c 'import secrets;print(secrets.token_hex(12))')
psql -q "$PGURL" -v api_pw="api-$PW" -v worker_pw="worker-$PW" -v relay_pw="relay-$PW" \
     -v readonly_pw="readonly-$PW" -f "$ROOT/deploy/kernel/roles.sql" >/dev/null
HOSTDB="${PGURL#*@}"
url_for() { echo "postgres://$1:$2-$PW@$HOSTDB"; }

log "starting kernel api / relay / worker (each as its own DB login)"
MK_DATABASE_URL="$(url_for mk_api_login api)" MK_BIND=127.0.0.1:8090 RUST_ACTION_KERNEL_ENABLED=1 \
  "$BIN/mk-action-api" >"$WORK/api.log" 2>&1 & PIDS+=($!)
MK_DATABASE_URL="$(url_for mk_relay_login relay)" MK_RELAY_ID=relay-smoke \
  "$BIN/mk-outbox-relay" >"$WORK/relay.log" 2>&1 & PIDS+=($!)
MK_DATABASE_URL="$(url_for mk_worker_login worker)" MK_WORKER_ID=worker-smoke MK_LEASE_SECS=60 MK_ALLOW_LOOPBACK_HTTP=1 \
  MK_MOBILE_INTAKE_URL="$AGENT/work-orders" MK_EGRESS_AUTHORITIES=127.0.0.1:8787 \
  "$BIN/mk-action-worker" >"$WORK/worker.log" 2>&1 & PIDS+=($!)
for i in $(seq 1 30); do curl -fsS "$API/health/ready" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS "$API/health/ready" >/dev/null || die "kernel api not ready"

log "starting FastAPI with the kernel wired in (no Python fallback)"
export RUST_ACTION_KERNEL_URL="$API" KERNEL_ASSERTION_PRIVATE_KEY="$DEV_PRIVATE_KEY" KERNEL_ASSERTION_KID=k1
export DATABASE_URL="sqlite:///$WORK/app.db" JWT_SECRET=dev-secret-dev-secret-dev-secret-123 \
       MASTER_KEY="$MK_MASTER_KEY" MK_ALLOW_DEV_SECRETS=1 RATE_LIMIT_PER_MINUTE=1000
(cd "$ROOT/backend" && python3 -m uvicorn app.main:app --port 8000 >"$WORK/app.log" 2>&1) & PIDS+=($!)
for i in $(seq 1 30); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$APP/docs" || true)" != 000 ] && break; sleep 1; done

TOK=$(curl -fsS "$APP/api/auth/signup" -H 'content-type: application/json' \
  -d '{"org_name":"Smoke Org","email":"admin@smoke.example.com","password":"superSecret123!","key_policy":"both"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
H=(-H "authorization: Bearer $TOK" -H 'content-type: application/json')
# Separate approver: outreach forbids self-approval by default, so a second
# consultant in the same tenant approves what the admin's agent proposed.
curl -fsS "$APP/api/auth/members" "${H[@]}" -d '{"email":"approver@smoke.example.com","password":"superSecret123!","role":"consultant"}' >/dev/null
TOK2=$(curl -fsS "$APP/api/auth/login" -H 'content-type: application/json' -d '{"email":"approver@smoke.example.com","password":"superSecret123!"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
H2=(-H "authorization: Bearer $TOK2" -H 'content-type: application/json')
TENANT=$(python3 -c "import jwt,sys,uuid;print(uuid.UUID(jwt.decode('$TOK',options={'verify_signature':False})['tid']))")
ops() { curl -sS -o "$WORK/out.json" -w '%{http_code}' "${H[@]}" "$@"; }
j() { python3 -c "import json,sys;d=json.load(open('$WORK/out.json'));print(eval(sys.argv[1]))" "$1"; }

log "kernel health through the app"
[ "$(ops "$APP/api/agent-ops/health")" = 200 ] || die "health via app"

log "register the device agent (tenant_admin via app)"
[ "$(ops -X POST "$APP/api/agent-ops/adapters" -d '{"agent_id":"moto-1","name":"Moto","platform":"android","version":"1","capabilities":["open","input"],"allowed_actions":[],"callback_authority":"127.0.0.1:8090"}')" = 201 ] || die "register adapter: $(cat "$WORK/out.json")"
SECRET=$(j 'd["enrollment_secret"]')

log "starting the ADB device agent in dry-run"
MK_AGENT_ID=moto-1 MK_TENANT_ID="$TENANT" MK_AGENT_SECRET="$SECRET" MK_EXECUTOR=dry-run \
  MK_CALLBACK_BASE="$API" MK_EVIDENCE_DIR="$WORK/evidence" \
  python3 "$ROOT/tools/mobile-agent-adb/agent.py" >"$WORK/agent.log" 2>&1 & PIDS+=($!)
for i in $(seq 1 20); do curl -fsS "$AGENT/health" >/dev/null 2>&1 && break; sleep 0.5; done

CONTACT=$(python3 -c 'import uuid;print(uuid.uuid4())')
CONTACT2=$(python3 -c 'import uuid;print(uuid.uuid4())')
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ); LATER=$(date -u -d '+30 min' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v+30M +%Y-%m-%dT%H:%M:%SZ)
grant() { ops -X POST "$APP/api/agent-ops/contacts/$1/permissions" -d "{\"channel\":\"sms\",\"scope\":[\"customer_requested_follow_up\"],\"source\":\"web_form\",\"proof_digest\":\"sha256:$(printf consent-%s "$1" | sha256sum | cut -c1-64)\",\"granted_at\":\"$NOW\",\"expires_at\":\"2027-01-01T00:00:00Z\"}"; }
propose_raw() { # $1 contact $2 to $3 idem
  ops -X POST "$APP/api/agent-ops/actions" -d "{\"origin\":\"agent\",\"request\":{\"workflow\":\"customer_follow_up\",\"action_kind\":\"send_sms\",\"tool_id\":\"mobile.sms.send.v1\",\"resource\":{\"type\":\"contact\",\"id\":\"$1\"},\"arguments\":{\"contact_id\":\"$1\",\"agent_id\":\"moto-1\",\"to\":\"$2\",\"template_id\":\"reorder_followup.v1\",\"rendered_text\":\"Hi! Your order shipped. Reply STOP to opt out.\"},\"purpose\":\"customer_requested_follow_up\",\"risk\":\"high\",\"requested_at\":\"$NOW\",\"expires_at\":\"$LATER\",\"idempotency_key\":\"$3\",\"evidence\":[]}}"; }
propose() { local c; c=$(propose_raw "$@"); case "$c" in 201|202) echo 201;; *) echo "$c";; esac; }
approve() { curl -sS -o "$WORK/out.json" -w '%{http_code}' "${H2[@]}" -X POST "$APP/api/agent-ops/actions/$1/approve" -d "{\"action_digest\":\"$2\",\"reason\":\"smoke\"}"; }
state() { ops "$APP/api/agent-ops/actions/$1" >/dev/null; j 'd["state"]'; }

log "gate 2: suppressed contact is refused at proposal"
[ "$(grant "$CONTACT2")" = 201 ] || die "grant2"
[ "$(ops -X POST "$APP/api/agent-ops/suppressions" -d '{"channel":"sms","destination":"+15555550199","reason":"stop","permanent":true,"source":"sms_reply"}')" = 201 ] || die "suppress"
code=$(propose "$CONTACT2" "+15555550199" "smoke-suppressed-1"); [ "$code" = 403 ] || die "suppressed proposal should be 403, got $code: $(cat "$WORK/out.json")"
log "  403 $(j 'd.get("code") or d["decision"]["code"]')"

log "gate 5: idempotent proposal + shared jti"
[ "$(grant "$CONTACT")" = 201 ] || die "grant"
[ "$(propose "$CONTACT" "+15555550100" "smoke-idempotent-1")" = 201 ] || die "propose: $(cat "$WORK/out.json")"
A1=$(j 'd["result"]["action_id"]'); D1=$(j 'd["result"]["action_digest"]')
c=$(propose_raw "$CONTACT" "+15555550100" "smoke-idempotent-1"); case "$c" in 200|201|202) ;; *) die "idempotent replay status $c";; esac
[ "$(j 'd["replayed"]')" = True ] && [ "$(j 'd["result"]["action_id"]')" = "$A1" ] || die "idempotency"
# jti replay: mint one assertion by hand and use it twice against the kernel directly
AS=$("$BIN/mk-devkeys" assert "$DEV_PRIVATE_KEY" "$TENANT" "$(python3 -c 'import uuid;print(uuid.uuid4())')" tenant_admin)
c1=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$API/internal/v1/kill-switch/tenant" -H "authorization: Bearer $AS" -H 'content-type: application/json' -d '{"dispatch_enabled":true}')
c2=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$API/internal/v1/kill-switch/tenant" -H "authorization: Bearer $AS" -H 'content-type: application/json' -d '{"dispatch_enabled":true}')
[ "$c1" = 204 ] && [ "$c2" = 401 ] || die "jti single-use expected 204 then 401, got $c1 $c2"

log "gate 3: revoked approval is never dispatched"
[ "$(propose "$CONTACT" "+15555550100" "smoke-revoked-1")" = 201 ] || die "propose rev"
A2=$(j 'd["result"]["action_id"]'); D2=$(j 'd["result"]["action_digest"]')
[ "$(approve "$A2" "$D2")" = 200 ] || die "approve rev: $(cat "$WORK/out.json")"
AP2=$(j 'd["approval"]["approval_id"]')
[ "$(ops -X POST "$APP/api/agent-ops/approvals/$AP2/revoke")" = 200 ] || die "revoke: $(cat "$WORK/out.json")"
sleep 6; s=$(state "$A2"); case "$s" in dispatching|completed) die "revoked action dispatched: $s";; esac
grep -q "$A2" "$WORK/agent.log" && die "revoked action reached the device agent"
log "  state after revoke: $s"

log "gate 4: tenant kill switch blocks dispatch (flipped AFTER proposal, BEFORE approval)"
[ "$(propose "$CONTACT" "+15555550100" "smoke-killswitch-1")" = 201 ] || die "propose kill: $(cat "$WORK/out.json")"
A3=$(j 'd["result"]["action_id"]'); D3=$(j 'd["result"]["action_digest"]')
[ "$(ops -X POST "$APP/api/agent-ops/kill-switch/tenant" -d '{"dispatch_enabled":false}')" = 204 ] || die "kill"
ac=$(approve "$A3" "$D3"); log "  approve under kill switch → $ac"
sleep 6; s=$(state "$A3"); case "$s" in dispatching|completed|failed_final) die "kill-switched action dispatched: $s";; esac
# And a fresh proposal while switched off is refused outright.
c=$(propose_raw "$CONTACT" "+15555550100" "smoke-killswitch-2"); [ "$c" = 403 ] && [ "$(j 'd["decision"]["code"]')" = dispatch_disabled ] || die "proposal under kill switch should be 403 dispatch_disabled, got $c"
python3 - "$WORK/evidence" "$A3" <<'EOF'
import sys,pathlib,uuid
d=pathlib.Path(sys.argv[1]); tid=uuid.UUID(sys.argv[2]).hex
assert not (d/f"{tid}.json").exists(), "kill-switched action executed on agent"
EOF
log "  state under kill switch: $s"
[ "$(ops -X POST "$APP/api/agent-ops/kill-switch/tenant" -d '{"dispatch_enabled":true}')" = 204 ] || die "unkill"

log "gate 1: approved action reaches the device agent; signed callback accepted"
[ "$(approve "$A1" "$D1")" = 200 ] || die "approve: $(cat "$WORK/out.json")"
for i in $(seq 1 40); do s=$(state "$A1"); case "$s" in completed|failed_final|failed_retryable|reconciliation_required) break;; esac; sleep 1; done
log "  terminal state: $s (dry-run agent reports failed/dry_run_no_device — honest, no device)"
case "$s" in completed|failed_final) ;; *) die "action did not reach the agent and back: $s";; esac
TID=$(python3 -c "import uuid;print(uuid.UUID('$A1').hex)")
[ -f "$WORK/evidence/$TID.json" ] || die "agent wrote no evidence bundle"
python3 - "$WORK/evidence/evidence-ledger.jsonl" <<'EOF'
import sys,json,hashlib
prev="0"*64
for line in open(sys.argv[1]):
    e=json.loads(line); h=e.pop("entry_hash")
    assert e["prev_hash"]==prev and hashlib.sha256(json.dumps(e,sort_keys=True,separators=(",",":")).encode()).hexdigest()==h
    prev=h
print("  agent evidence chain ok, head", prev[:16])
EOF
grep -q "dry_run_no_device\|callback" "$WORK/api.log" || true

log "gate 6: kernel audit chain verifies (read-only identity)"
MK_DATABASE_URL="$(url_for mk_readonly_login readonly)" "$BIN/mk-audit-verifier" | tail -3

log "gate 7: identities are least-privilege (API cannot claim outbox; relay cannot read approvals; readonly cannot write)"
! psql -q "$(url_for mk_api_login api)" -c "UPDATE kernel.outbox_events SET leased_by='x' WHERE false" >/dev/null 2>&1 || die "api login can touch outbox claims"
! psql -q "$(url_for mk_relay_login relay)" -c "SELECT 1 FROM kernel.approvals LIMIT 1" >/dev/null 2>&1 || die "relay login can read approvals"
! psql -q "$(url_for mk_readonly_login readonly)" -c "INSERT INTO kernel.kill_switches (scope,tenant_id,dispatch_enabled,changed_by) VALUES ('tenant','$TENANT',false,'x')" >/dev/null 2>&1 || die "readonly login can write"
! psql -q "$(url_for mk_api_login api)" -c "DELETE FROM kernel.audit_events WHERE false" >/dev/null 2>&1 || die "api login can delete audit"

log "no PII in kernel/agent logs"
! grep -q "5555550100\|Your order shipped" "$WORK/api.log" "$WORK/worker.log" "$WORK/relay.log" "$WORK/agent.log" || die "PII leaked to logs"

log "ALL GATES PASSED — artifacts in $WORK"
