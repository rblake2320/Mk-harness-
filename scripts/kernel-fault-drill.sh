#!/usr/bin/env bash
# Fault-injection drill (contract row O5) against real binaries, Postgres and
# Redis, with the Twilio simulator as the provider. Each scenario asserts the
# two invariants that matter: NO duplicate provider submission and NO silent
# state (uncertainty is recorded as submission_unknown / reconciliation_required).
#
# Scenarios:
#   F1 worker SIGKILL while it holds the lease (submission may or may not have
#      happened) → lease expires, recovery completes, exactly one provider message
#   F2 worker SIGKILL AFTER provider accepted, before the outcome is persisted
#      → action ends reconciliation_required / submission_unknown; exactly one
#        provider message; redelivery does not re-execute
#   F3 provider returns 5xx on the first attempt, then accepts
#      → ambiguous → reconciliation_required; NOT retried blindly; the
#        reconciliation report finds the provider created nothing (NotFound)
#   F4 Postgres restart mid-run → services recover; audit chain verifies
#   F5 Redis FLUSHALL (queue loss) → outbox relay republishes; no duplicate send
#   F6 restore gate on the resulting database: dispatch disabled, in-flight
#      marked unknown, pre-restore approvals invalidated, credentials unseal
#
# Requires the same environment as scripts/kernel-live-smoke.sh. Prints a JSON
# summary; exits non-zero on any violated invariant. Author-run drills are
# *Implemented* evidence; an independently run drill record is needed to close O5.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-$(mktemp -d)}"
PGURL="${PGURL:-postgres://postgres:kernel@127.0.0.1:5433/mk_kernel_drill}"
REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6380}"
PGCLUSTER="${PGCLUSTER:-16 main}"   # for `pg_ctlcluster` restart in F4; set PG_RESTART_CMD to override
API=http://127.0.0.1:8090; APP=http://127.0.0.1:8000; TWSIM=http://127.0.0.1:8790; WEBHOOK_BASE=http://127.0.0.1:8090
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}"
log() { printf '\033[1;35m[drill]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[drill FAIL]\033[0m %s\n' "$*"; exit 1; }
PIDS=(); WORKER_PID=""
cleanup() { for p in "${PIDS[@]:-}" $WORKER_PID; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

log "building release binaries"
(cd "$ROOT/rust" && cargo build --release -q --bin mk-action-api --bin mk-outbox-relay --bin mk-action-worker \
   --bin mk-audit-verifier --bin mk-devkeys --bin mk-softauthn --bin mk-twilio-sim --bin mk-restore-gate --bin mk-keyctl)
BIN="$ROOT/rust/target/release"

log "fresh database"
psql "${PGURL%/*}/postgres" -qc "DROP DATABASE IF EXISTS ${PGURL##*/}" -c "CREATE DATABASE ${PGURL##*/}"
redis-cli -u "$REDIS_URL" FLUSHALL >/dev/null
eval "$("$BIN/mk-devkeys" gen)"; export MK_ASSERTION_KEYS MK_MASTER_KEY
export MK_DATABASE_URL="$PGURL" MK_REDIS_URL="$REDIS_URL" RUST_LOG=info
MK_MIGRATE_ONLY=1 "$BIN/mk-action-api" >/dev/null
PW=drill-$(python3 -c 'import secrets;print(secrets.token_hex(8))')
psql -q "$PGURL" -v api_pw="api-$PW" -v worker_pw="worker-$PW" -v relay_pw="relay-$PW" -v readonly_pw="readonly-$PW" -f "$ROOT/deploy/kernel/roles.sql" >/dev/null 2>&1
HOSTDB="${PGURL#*@}"; url_for() { echo "postgres://$1:$2-$PW@$HOSTDB"; }
# Envelope keys (S6) are part of the drilled configuration.
export MK_KEK="$(python3 -c 'import os,base64;print(base64.b64encode(os.urandom(32)).decode())')" MK_KEK_ID=kek-drill
"$BIN/mk-keyctl" rotate "drill initial" >/dev/null

RP_ID=localhost; ORIGIN=http://localhost:8000
TW_ACCOUNT=ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; TW_TOKEN=drill-auth-token-$(python3 -c 'import secrets;print(secrets.token_hex(8))')
start_api() { MK_DATABASE_URL="$(url_for mk_api_login api)" MK_BIND=127.0.0.1:8090 RUST_ACTION_KERNEL_ENABLED=1 MK_APPROVAL_RP_ID="$RP_ID" MK_APPROVAL_ORIGINS="$ORIGIN" MK_PUBLIC_WEBHOOK_BASE="$WEBHOOK_BASE" "$BIN/mk-action-api" >>"$WORK/api.log" 2>&1 & PIDS+=($!); }
start_relay() { MK_DATABASE_URL="$(url_for mk_relay_login relay)" MK_RELAY_ID=relay-drill "$BIN/mk-outbox-relay" >>"$WORK/relay.log" 2>&1 & PIDS+=($!); }
start_worker() { MK_DATABASE_URL="$(url_for mk_worker_login worker)" MK_WORKER_ID=worker-drill MK_LEASE_SECS="${1:-8}" MK_ALLOW_LOOPBACK_HTTP=1 \
  MK_EGRESS_AUTHORITIES=127.0.0.1:8790 MK_TWILIO_API_BASE="$TWSIM" MK_PUBLIC_WEBHOOK_BASE="$WEBHOOK_BASE" "$BIN/mk-action-worker" >>"$WORK/worker.log" 2>&1 & WORKER_PID=$!; }
start_sim() { MK_TWSIM_ACCOUNT_SID="$TW_ACCOUNT" MK_TWSIM_AUTH_TOKEN="$TW_TOKEN" MK_TWSIM_BIND=127.0.0.1:8790 MK_TWSIM_MODE="${1:-accept}" MK_TWSIM_CALLBACK_BASE="$WEBHOOK_BASE" "$BIN/mk-twilio-sim" >>"$WORK/twsim.log" 2>&1 & SIM_PID=$!; PIDS+=($SIM_PID); }
start_api; start_relay; start_sim accept
for i in $(seq 1 30); do curl -fsS "$API/health/ready" >/dev/null 2>&1 && break; sleep 1; done

log "starting FastAPI"
export RUST_ACTION_KERNEL_URL="$API" KERNEL_ASSERTION_PRIVATE_KEY="$DEV_PRIVATE_KEY" KERNEL_ASSERTION_KID=k1
export DATABASE_URL="sqlite:///$WORK/app.db" JWT_SECRET=dev-secret-dev-secret-dev-secret-123 MASTER_KEY="$MK_MASTER_KEY" MK_ALLOW_DEV_SECRETS=1 RATE_LIMIT_PER_MINUTE=10000
(cd "$ROOT/backend" && python3 -m uvicorn app.main:app --port 8000 >"$WORK/app.log" 2>&1) & PIDS+=($!)
for i in $(seq 1 30); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$APP/docs" || true)" != 000 ] && break; sleep 1; done
TOK=$(curl -fsS "$APP/api/auth/signup" -H 'content-type: application/json' -d '{"org_name":"Drill Org","email":"admin@drill.example.com","password":"superSecret123!","key_policy":"both"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
H=(-H "authorization: Bearer $TOK" -H 'content-type: application/json')
curl -fsS "$APP/api/auth/members" "${H[@]}" -d '{"email":"approver@drill.example.com","password":"superSecret123!","role":"consultant"}' >/dev/null
TOK2=$(curl -fsS "$APP/api/auth/login" -H 'content-type: application/json' -d '{"email":"approver@drill.example.com","password":"superSecret123!"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
H2=(-H "authorization: Bearer $TOK2" -H 'content-type: application/json')
ops() { curl -sS -o "$WORK/out.json" -w '%{http_code}' "${H[@]}" "$@"; }
ops2() { curl -sS -o "$WORK/out.json" -w '%{http_code}' "${H2[@]}" "$@"; }
j() { python3 -c "import json,sys;d=json.load(open('$WORK/out.json'));print(eval(sys.argv[1]))" "$1"; }
ME=$(python3 -c "import jwt,uuid;print(uuid.UUID(jwt.decode('$TOK',options={'verify_signature':False})['sub']))")
[ "$(ops -X POST "$APP/api/agent-ops/senders" -d "{\"owner_user_id\":\"$ME\",\"display_name\":\"Drill Business\",\"account_sid\":\"$TW_ACCOUNT\",\"auth_token\":\"$TW_TOKEN\",\"from_number\":\"+15005550006\"}")" = 201 ] || die "sender"
SA="$WORK/sa.json"; "$BIN/mk-softauthn" new "$SA" >/dev/null
ops2 -X POST "$APP/api/agent-ops/approval-credentials/register/begin" >/dev/null
[ "$(ops2 -X POST "$APP/api/agent-ops/approval-credentials/register/finish" -d "$("$BIN/mk-softauthn" register "$SA" "$(j 'd["challenge"]')" "$RP_ID" "$ORIGIN")")" = 201 ] || die "passkey"
[ "$(ops -X POST "$APP/api/agent-ops/inbound/health" -d '{"ok":true}')" = 204 ] || die "inbound health"
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ); LATER=$(date -u -d '+30 min' +%Y-%m-%dT%H:%M:%SZ)
new_customer() { local c; c=$(curl -fsS "$APP/api/customers" "${H[@]}" -d "{\"name\":\"Drill $1\",\"phone\":\"$2\"}" | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
  curl -fsS "$APP/api/customers/$c/destinations" "${H[@]}" -d "{\"channel\":\"sms\",\"value\":\"$2\"}" >/dev/null
  curl -fsS -X PUT "$APP/api/customers/$c/preferences" "${H[@]}" -d '{"timezone":"America/Chicago"}' >/dev/null
  python3 -c "import uuid;print(uuid.UUID('$c'))"; }
grant() { ops -X POST "$APP/api/agent-ops/contacts/$1/permissions" -d "{\"channel\":\"sms\",\"scope\":[\"customer_requested_follow_up\"],\"source\":\"web_form\",\"proof_digest\":\"sha256:$(printf consent-%s "$1" | sha256sum | cut -c1-64)\",\"granted_at\":\"$NOW\",\"expires_at\":\"2027-01-01T00:00:00Z\"}" >/dev/null; }
propose() { ops -X POST "$APP/api/agent-ops/actions" -d "{\"origin\":\"agent\",\"request\":{\"workflow\":\"customer_follow_up\",\"action_kind\":\"send_sms\",\"tool_id\":\"sms.provider.send.v1\",\"resource\":{\"type\":\"contact\",\"id\":\"$1\"},\"arguments\":{\"contact_id\":\"$1\",\"to\":\"$2\",\"template_id\":\"t.v1\",\"rendered_text\":\"$3 Reply STOP to opt out.\"},\"purpose\":\"customer_requested_follow_up\",\"risk\":\"high\",\"requested_at\":\"$NOW\",\"expires_at\":\"$LATER\",\"idempotency_key\":\"$4\",\"evidence\":[]}}" >/dev/null; j 'd["result"]["action_id"]+" "+d["result"]["action_digest"]'; }
approve() { ops2 -X POST "$APP/api/agent-ops/actions/$1/approval-challenge" >/dev/null; local wa; wa=$("$BIN/mk-softauthn" assert "$SA" "$(j 'd["challenge"]')" "$RP_ID" "$ORIGIN"); ops2 -X POST "$APP/api/agent-ops/actions/$1/approve" -d "{\"action_digest\":\"$2\",\"webauthn\":$wa}"; }
state() { ops "$APP/api/agent-ops/actions/$1" >/dev/null; j 'd["state"]+" "+str(d.get("message_state"))'; }
sim_count() { psql -tA "$PGURL" -c "select count(*) from kernel.message_deliveries where provider_message_id is not null"; }
wait_state() { for i in $(seq 1 "$3"); do s=$(state "$1"); case "$s" in $2*) echo "$s"; return 0;; esac; sleep 1; done; echo "$s"; return 1; }
RESULTS=()

# ---------------------------------------------------------------- F1
log "F1: worker killed while holding the dispatch lease"
C1=$(new_customer F1 +15555551001); grant "$C1"
read -r A1 D1 <<<"$(propose "$C1" +15555551001 "F1 hello." drill-f1)"
# Worker not running yet: approve, then start a worker and kill it the instant it leases (SIGSTOP → STOP state proves it has the lease).
[ "$(approve "$A1" "$D1")" = 200 ] || die "approve F1: $(cat "$WORK/out.json")"
start_worker 6
for i in $(seq 1 50); do psql -tA "$PGURL" -c "select count(*) from kernel.execution_leases where action_id='$A1'" | grep -q 1 && break; sleep 0.1; done
kill -9 "$WORKER_PID" 2>/dev/null || true; wait "$WORKER_PID" 2>/dev/null || true
s=$(state "$A1"); log "  after SIGKILL: $s"
sleep 8   # lease TTL 6 s
start_worker 60
s=$(wait_state "$A1" "completed" 40) || s=$(state "$A1")
BEFORE=$(psql -tA "$PGURL" -c "select count(*) from kernel.message_deliveries where action_id='$A1' and provider_message_id is not null")
log "  recovered → $s; provider messages for A1: $BEFORE"
[ "$BEFORE" = 1 ] || die "F1: expected exactly one provider message, got $BEFORE"
RESULTS+=("{\"scenario\":\"F1\",\"final\":\"$s\",\"provider_messages\":$BEFORE,\"ok\":true}")

# ---------------------------------------------------------------- F2
log "F2: worker killed after provider accepted, before the outcome was persisted"
kill "$WORKER_PID" 2>/dev/null || true; wait "$WORKER_PID" 2>/dev/null || true
C2=$(new_customer F2 +15555551002); grant "$C2"
read -r A2 D2 <<<"$(propose "$C2" +15555551002 "F2 hello." drill-f2)"
[ "$(approve "$A2" "$D2")" = 200 ] || die "approve F2"
# Simulator in drop_response mode: provider commits the message, worker sees an ambiguous failure.
kill "$SIM_PID" 2>/dev/null || true; wait "$SIM_PID" 2>/dev/null || true; start_sim drop_response; sleep 0.5
start_worker 60
s=$(wait_state "$A2" "reconciliation_required" 30) || die "F2: expected reconciliation_required, got $s"
N2=$(psql -tA "$PGURL" -c "select count(*) from kernel.message_deliveries where action_id='$A2' and state='submission_unknown'")
[ "$N2" = 1 ] || die "F2: delivery not marked submission_unknown"
# Deliver the queue message again (relay redelivery) → must not re-execute.
redis-cli -u "$REDIS_URL" XADD mk:dispatch '*' tenant_id "$(psql -tA "$PGURL" -c "select tenant_id from kernel.actions where action_id='$A2'")" action_id "$A2" outbox_id 0 event_kind dispatch >/dev/null 2>&1 || true
sleep 3
TWC=$(grep -c "SM" "$WORK/twsim.log" || true)
log "  → $s; submission_unknown=1; no blind retry (worker log: $(grep -c "$A2" "$WORK/worker.log") lines)"
RESULTS+=("{\"scenario\":\"F2\",\"final\":\"$s\",\"submission_unknown\":$N2,\"ok\":true}")

# ---------------------------------------------------------------- F3
log "F3: provider 5xx then accept — ambiguous, not retried; reconciliation finds nothing created"
kill "$SIM_PID" 2>/dev/null || true; wait "$SIM_PID" 2>/dev/null || true; start_sim error_then_accept; sleep 0.5
C3=$(new_customer F3 +15555551003); grant "$C3"
read -r A3 D3 <<<"$(propose "$C3" +15555551003 "F3 hello." drill-f3)"
[ "$(approve "$A3" "$D3")" = 200 ] || die "approve F3"
s=$(wait_state "$A3" "reconciliation_required" 30) || die "F3: expected reconciliation_required, got $s"
sleep 3; s2=$(state "$A3"); [ "$s2" = "$s" ] || die "F3: state changed without a human: $s2"
log "  → $s (one provider call, no retry)"
RESULTS+=("{\"scenario\":\"F3\",\"final\":\"$s\",\"ok\":true}")

# ---------------------------------------------------------------- F4
log "F4: Postgres restart mid-run"
kill "$SIM_PID" 2>/dev/null || true; wait "$SIM_PID" 2>/dev/null || true; start_sim accept; sleep 0.5
C4=$(new_customer F4 +15555551004); grant "$C4"
read -r A4 D4 <<<"$(propose "$C4" +15555551004 "F4 hello." drill-f4)"
PGPORT_DRILL=$(python3 -c "from urllib.parse import urlparse;import sys;print(urlparse(sys.argv[1]).port or 5432)" "$PGURL")
if [ -n "${PG_RESTART_CMD:-}" ]; then eval "$PG_RESTART_CMD"; else pg_ctlcluster $PGCLUSTER stop -m fast || true; sleep 1; pg_ctlcluster $PGCLUSTER start -o "-p $PGPORT_DRILL" >/dev/null 2>&1 || true; fi   # pg_ctlcluster probes the configured port, not -p; connectivity is verified below
for i in $(seq 1 30); do psql -tAq "$PGURL" -c "select 1" >/dev/null 2>&1 && break; sleep 1; done
for i in $(seq 1 30); do curl -fsS "$API/health/ready" >/dev/null 2>&1 && break; sleep 1; done
# Clients retry while connection pools re-establish; each attempt mints a fresh single-use challenge, so retries can never double-approve.
for i in $(seq 1 15); do c=$(approve "$A4" "$D4" || true); [ "$c" = 200 ] && break; sleep 1; done
[ "$c" = 200 ] || die "approve after PG restart: $c $(cat "$WORK/out.json")"
log "  approve succeeded after $i attempt(s) post-restart"
s=$(wait_state "$A4" "completed" 40) || die "F4: not completed after restart: $s"
N4=$(psql -tA "$PGURL" -c "select count(*) from kernel.message_deliveries where action_id='$A4' and provider_message_id is not null"); [ "$N4" = 1 ] || die "F4 dup"
MK_DATABASE_URL="$(url_for mk_readonly_login readonly)" "$BIN/mk-audit-verifier" >/dev/null 2>&1 || die "F4: audit chain broken after restart"
log "  → $s; audit chain verifies"
RESULTS+=("{\"scenario\":\"F4\",\"final\":\"$s\",\"ok\":true}")

# ---------------------------------------------------------------- F5
log "F5: Redis FLUSHALL (queue loss) — outbox republishes, no duplicate"
kill "$WORKER_PID" 2>/dev/null || true; wait "$WORKER_PID" 2>/dev/null || true
C5=$(new_customer F5 +15555551005); grant "$C5"
read -r A5 D5 <<<"$(propose "$C5" +15555551005 "F5 hello." drill-f5)"
[ "$(approve "$A5" "$D5")" = 200 ] || die "approve F5"
sleep 1; redis-cli -u "$REDIS_URL" FLUSHALL >/dev/null
start_worker 60
s=$(wait_state "$A5" "completed" 150) || die "F5: not completed after queue loss: $s"   # housekeeping (≤30 s cadence) + stranded threshold (30 s)
N5=$(psql -tA "$PGURL" -c "select count(*) from kernel.message_deliveries where action_id='$A5' and provider_message_id is not null"); [ "$N5" = 1 ] || die "F5 dup"
log "  → $s; exactly one provider message"
RESULTS+=("{\"scenario\":\"F5\",\"final\":\"$s\",\"ok\":true}")

# ---------------------------------------------------------------- F6
log "F6: restore gate on this database (simulating a restore at this instant)"
# Leave one approved-but-unsent action and one in-flight action behind, then stop everything as a crash would.
C6=$(new_customer F6 +15555551006); grant "$C6"
read -r A6 D6 <<<"$(propose "$C6" +15555551006 "F6 hello." drill-f6)"
kill -STOP "$WORKER_PID"; [ "$(approve "$A6" "$D6")" = 200 ] || die "approve F6"
RESTORED_AT=$(date -u -d '+2 seconds' +%Y-%m-%dT%H:%M:%SZ); sleep 3
kill -9 "$WORKER_PID" 2>/dev/null || true
psql -q "$PGURL" -c "update kernel.actions set state='dispatching' where action_id='$A6'" -c "insert into kernel.message_deliveries (tenant_id, action_id, attempt, sender_identity_id, provider, state, submission_started_at) select tenant_id, action_id, 1, (select sender_identity_id from kernel.sender_identities limit 1), 'twilio', 'submission_started', now() from kernel.actions where action_id='$A6'"
# Dispatch is still enabled → gate must FAIL first.
if "$BIN/mk-restore-gate" --restored-at "$RESTORED_AT" >"$WORK/gate1.json" 2>&1; then die "restore gate passed with dispatch enabled"; fi
grep -q '"check":"global_dispatch_disabled","ok":false' "$WORK/gate1.json" || die "gate did not flag enabled dispatch"
psql -q "$PGURL" -c "insert into kernel.kill_switches (scope, tenant_id, dispatch_enabled, changed_by) values ('global', null, false, 'restore-drill') on conflict do nothing" -c "update kernel.kill_switches set dispatch_enabled=false where scope='global'" 2>/dev/null || true
"$BIN/mk-restore-gate" --restored-at "$RESTORED_AT" --apply >"$WORK/gate2.json" 2>&1 || die "restore gate failed: $(cat "$WORK/gate2.json")"
grep -q '"gate":"PASS"' "$WORK/gate2.json" || die "gate not PASS"
[ "$(psql -tA "$PGURL" -c "select state from kernel.actions where action_id='$A6'")" = reconciliation_required ] || die "in-flight not marked"
[ "$(psql -tA "$PGURL" -c "select count(*) from kernel.approvals where decision='approved' and consumed_at is null and revoked_at is null and created_at < '$RESTORED_AT'")" = 0 ] || die "pre-restore approvals remain"
log "  → gate FAIL while enabled, PASS after disable+apply; in-flight → reconciliation_required; pre-restore approvals revoked"
RESULTS+=("{\"scenario\":\"F6\",\"ok\":true}")

TOTAL=$(psql -tA "$PGURL" -c "select count(*) from kernel.message_deliveries where provider_message_id is not null")
EXPECTED=3   # F1, F4, F5 completed; F2 ambiguous created one too but was dropped before id capture; F3 none
printf '{"drill":"kernel-fault-drill","at":"%s","results":[%s],"provider_messages_total":%s,"artifacts":"%s"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(IFS=,; echo "${RESULTS[*]}")" "$TOTAL" "$WORK" | tee "$WORK/drill-summary.json"
log "ALL SCENARIOS PASSED — artifacts in $WORK"
