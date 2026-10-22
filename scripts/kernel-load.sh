#!/usr/bin/env bash
# Load run against a real kernel stack (contract O2–O4) with the provider
# simulator as the transport. Stands up Postgres roles, api, relay, N workers
# and the Twilio simulator exactly as the live smoke does, then drives
# `mk-loadgen` at the requested rates and writes `load-report.json`.
#
#   scripts/kernel-load.sh [--duration-secs 60] [--proposals-per-sec 2] \
#                          [--reads-per-sec 10] [--inbound-per-sec 1] [--tenants 2] [--workers 2]
#
# The report's `run.envelope_run` is true ONLY for an 8 h run at ≥20 proposal/s
# and ≥100 read/s. Anything shorter is a functional load check and the report
# says so; it is never qualification evidence (rows O2–O4 stay Not demonstrated
# until a second person runs the envelope and records it under evidence/).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-$(mktemp -d)}"
PGURL="${PGURL:-postgres://postgres:kernel@127.0.0.1:5433/mk_kernel_load}"
REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6380}"
API=http://127.0.0.1:8091
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}"
log() { printf '\033[1;33m[load]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[load FAIL]\033[0m %s\n' "$*"; exit 1; }
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
WORKERS=2; LOADARGS=()
while [ $# -gt 0 ]; do case "$1" in --workers) WORKERS="$2"; shift 2;; *) LOADARGS+=("$1"); shift;; esac; done

log "building release binaries"
(cd "$ROOT/rust" && cargo build --release -q --bin mk-action-api --bin mk-outbox-relay --bin mk-action-worker \
   --bin mk-devkeys --bin mk-twilio-sim --bin mk-keyctl --bin mk-loadgen)
BIN="$ROOT/rust/target/release"

log "fresh database"
psql "${PGURL%/*}/postgres" -qc "DROP DATABASE IF EXISTS ${PGURL##*/}" -c "CREATE DATABASE ${PGURL##*/}"
redis-cli -u "$REDIS_URL" FLUSHALL >/dev/null
eval "$("$BIN/mk-devkeys" gen)"
export MK_ASSERTION_KEYS MK_MASTER_KEY
export MK_KEK="$(python3 -c 'import os,base64;print(base64.b64encode(os.urandom(32)).decode())')" MK_KEK_ID=kek-load
export MK_DATABASE_URL="$PGURL" MK_REDIS_URL="$REDIS_URL" RUST_LOG=warn
MK_MIGRATE_ONLY=1 "$BIN/mk-action-api" >/dev/null
"$BIN/mk-keyctl" rotate "initial" >/dev/null
PW=load-$(python3 -c 'import secrets;print(secrets.token_hex(12))')
psql -q "$PGURL" -v api_pw="api-$PW" -v worker_pw="worker-$PW" -v relay_pw="relay-$PW" -v readonly_pw="readonly-$PW" -f "$ROOT/deploy/kernel/roles.sql" >/dev/null
HOSTDB="${PGURL#*@}"; url_for() { echo "postgres://$1:$2-$PW@$HOSTDB"; }

RP_ID=localhost; ORIGIN=http://localhost:8000; WEBHOOK_BASE=$API
TWSIM=http://127.0.0.1:8791; TW_ACCOUNT=ACcccccccccccccccccccccccccccccccc; TW_TOKEN=load-auth-token-$(python3 -c 'import secrets;print(secrets.token_hex(8))')
log "starting api, relay, $WORKERS worker(s), simulator"
MK_DATABASE_URL="$(url_for mk_api_login api)" MK_BIND=127.0.0.1:8091 RUST_ACTION_KERNEL_ENABLED=1 \
  MK_APPROVAL_RP_ID="$RP_ID" MK_APPROVAL_ORIGINS="$ORIGIN" MK_PUBLIC_WEBHOOK_BASE="$WEBHOOK_BASE" \
  "$BIN/mk-action-api" >"$WORK/api.log" 2>&1 & PIDS+=($!)
MK_DATABASE_URL="$(url_for mk_relay_login relay)" MK_RELAY_ID=relay-load "$BIN/mk-outbox-relay" >"$WORK/relay.log" 2>&1 & PIDS+=($!)
for i in $(seq 1 "$WORKERS"); do
  MK_DATABASE_URL="$(url_for mk_worker_login worker)" MK_WORKER_ID="worker-load-$i" MK_LEASE_SECS=60 MK_ALLOW_LOOPBACK_HTTP=1 \
    MK_EGRESS_AUTHORITIES=127.0.0.1:8791,127.0.0.1:8091 MK_TWILIO_API_BASE="$TWSIM" MK_PUBLIC_WEBHOOK_BASE="$WEBHOOK_BASE" \
    MK_METRICS_BIND="127.0.0.1:$((9200 + i))" MK_WORKER_BATCH=32 \
    "$BIN/mk-action-worker" >"$WORK/worker-$i.log" 2>&1 & PIDS+=($!)
done
MK_TWSIM_ACCOUNT_SID="$TW_ACCOUNT" MK_TWSIM_AUTH_TOKEN="$TW_TOKEN" MK_TWSIM_BIND=127.0.0.1:8791 MK_TWSIM_CALLBACK_BASE="$WEBHOOK_BASE" \
  "$BIN/mk-twilio-sim" >"$WORK/twsim.log" 2>&1 & PIDS+=($!)
for i in $(seq 1 30); do curl -fsS "$API/health/ready" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS "$API/health/ready" >/dev/null || die "kernel api not ready"
# Enable global dispatch directly for the load environment (owner login; a production
# environment does this through the operator passkey step-up, never like this).
psql -q "$PGURL" -c "UPDATE kernel.kill_switches SET dispatch_enabled = true, changed_by = 'load-script', changed_at = now() WHERE scope = 'global'"

log "running mk-loadgen ${LOADARGS[*]:-defaults}"
set +e
MK_KERNEL_URL="$API" MK_WEBHOOK_BASE="$WEBHOOK_BASE" MK_TWSIM_ACCOUNT_SID="$TW_ACCOUNT" MK_TWSIM_AUTH_TOKEN="$TW_TOKEN" \
  MK_LOAD_RP_ID="$RP_ID" MK_LOAD_ORIGIN="$ORIGIN" DEV_PRIVATE_KEY="$DEV_PRIVATE_KEY" \
  "$BIN/mk-loadgen" "${LOADARGS[@]}" --out "$WORK/load-report.json" 2>"$WORK/loadgen.log"; rc=$?
set -e
# Worker metrics snapshot at the end (queue drained? sampler errors?).
curl -fsS "http://127.0.0.1:9201/metrics" > "$WORK/worker-metrics.txt" 2>/dev/null || true
# Audit integrity after load.
grep -E "mk_audit_head_mismatches|mk_queue_depth|mk_actions_reconciliation_required|mk_dead_letters" "$WORK/worker-metrics.txt" | grep -v "^#" || true
! grep -q "PII\|+1555" "$WORK/api.log" "$WORK/worker-1.log" || die "PII leaked to logs"
log "report: $WORK/load-report.json (loadgen rc=$rc)"
python3 - "$WORK/load-report.json" <<'EOF2'
import json,sys
r=json.load(open(sys.argv[1]))
print(json.dumps(r["counts"]))
for row in r["slo"]:
    print(f'{row["id"]:<22} pass={row["pass"]}  measured={json.dumps(row["measured"])}')
print("envelope_run:", r["run"]["envelope_run"], "| all_measured_slos_pass:", r["verdict"]["all_measured_slos_pass"])
EOF2
exit $rc
