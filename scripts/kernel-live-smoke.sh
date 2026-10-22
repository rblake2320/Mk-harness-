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
# Customer timezone where it is ~noon now, so contact-hours policy (08–21 local) passes at any UTC hour.
NOON_TZ=$(python3 -c 'import datetime;o=max(-12,min(14,12-datetime.datetime.now(datetime.timezone.utc).hour));print("Etc/UTC" if o==0 else ("Etc/GMT-%d"%o if o>0 else "Etc/GMT+%d"%-o))')
WORK="${WORK:-$(mktemp -d)}"; mkdir -p "$WORK"
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
   --bin mk-action-worker --bin mk-audit-verifier --bin mk-devkeys --bin mk-softauthn --bin mk-twilio-sim \
   --bin mk-keyctl --bin mk-restore-gate)
BIN="$ROOT/rust/target/release"

log "fresh database"
psql "${PGURL%/*}/postgres" -qc "DROP DATABASE IF EXISTS ${PGURL##*/}" -c "CREATE DATABASE ${PGURL##*/}"
redis-cli -u "$REDIS_URL" FLUSHALL >/dev/null

eval "$("$BIN/mk-devkeys" gen)"      # MK_ASSERTION_KEYS, DEV_PRIVATE_KEY, MK_MASTER_KEY
export MK_ASSERTION_KEYS MK_MASTER_KEY
# Envelope keyring as in production: a KEK wraps the per-version data keys (WP09).
export MK_KEK="$(python3 -c 'import os,base64;print(base64.b64encode(os.urandom(32)).decode())')" MK_KEK_ID=kek-smoke
export MK_DATABASE_URL="$PGURL" MK_REDIS_URL="$REDIS_URL" RUST_LOG=info
MK_MIGRATE_ONLY=1 "$BIN/mk-action-api" >/dev/null
# Bring-up step: the first wrapped data-key version, so nothing is ever sealed under the legacy single key.
"$BIN/mk-keyctl" rotate "initial" >/dev/null || die "keyctl initial rotate"

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
# Human-approval authority configured as in production: approvals require a
# kernel-verified WebAuthn assertion (rp id = the approval UI's domain).
RP_ID=localhost; ORIGIN=http://localhost:8000
# Provider webhooks are signed over this public base (what the provider is configured with).
WEBHOOK_BASE=http://127.0.0.1:8090
MK_DATABASE_URL="$(url_for mk_api_login api)" MK_BIND=127.0.0.1:8090 RUST_ACTION_KERNEL_ENABLED=1 \
  MK_APPROVAL_RP_ID="$RP_ID" MK_APPROVAL_ORIGINS="$ORIGIN" MK_PUBLIC_WEBHOOK_BASE="$WEBHOOK_BASE" \
  "$BIN/mk-action-api" >"$WORK/api.log" 2>&1 & PIDS+=($!)
MK_DATABASE_URL="$(url_for mk_relay_login relay)" MK_RELAY_ID=relay-smoke \
  "$BIN/mk-outbox-relay" >"$WORK/relay.log" 2>&1 & PIDS+=($!)
TWSIM=http://127.0.0.1:8790; TW_ACCOUNT=ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; TW_TOKEN=smoke-auth-token-$(python3 -c 'import secrets;print(secrets.token_hex(8))')
MK_DATABASE_URL="$(url_for mk_worker_login worker)" MK_WORKER_ID=worker-smoke MK_LEASE_SECS=60 MK_ALLOW_LOOPBACK_HTTP=1 \
  MK_MOBILE_INTAKE_URL="$AGENT/work-orders" MK_EGRESS_AUTHORITIES=127.0.0.1:8787,127.0.0.1:8790,127.0.0.1:8090 \
  MK_TWILIO_API_BASE="$TWSIM" MK_PUBLIC_WEBHOOK_BASE="$WEBHOOK_BASE" \
  "$BIN/mk-action-worker" >"$WORK/worker.log" 2>&1 & WORKER_PID=$!; PIDS+=($WORKER_PID)
MK_TWSIM_ACCOUNT_SID="$TW_ACCOUNT" MK_TWSIM_AUTH_TOKEN="$TW_TOKEN" MK_TWSIM_BIND=127.0.0.1:8790 MK_TWSIM_CALLBACK_BASE="$WEBHOOK_BASE" \
  "$BIN/mk-twilio-sim" >"$WORK/twsim.log" 2>&1 & PIDS+=($!)
for i in $(seq 1 30); do curl -fsS "$API/health/ready" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS "$API/health/ready" >/dev/null || die "kernel api not ready"

log "starting FastAPI with the kernel wired in (no Python fallback)"
export RUST_ACTION_KERNEL_URL="$API" KERNEL_ASSERTION_PRIVATE_KEY="$DEV_PRIVATE_KEY" KERNEL_ASSERTION_KID=k1
export DATABASE_URL="sqlite:///$WORK/app.db" JWT_SECRET=dev-secret-dev-secret-dev-secret-123 \
       MASTER_KEY="$MK_MASTER_KEY" MK_ALLOW_DEV_SECRETS=1 RATE_LIMIT_PER_MINUTE=1000
(cd "$ROOT/backend" && exec python3 -m uvicorn app.main:app --port 8000 >"$WORK/app.log" 2>&1) & PIDS+=($!)
for i in $(seq 1 30); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$APP/docs" || true)" != 000 ] && break; sleep 1; done

TOK=$(curl -fsS "$APP/api/auth/signup" -H 'content-type: application/json' \
  -d '{"org_name":"Smoke Org","email":"admin@smoke.example.com","password":"superSecret123!","key_policy":"both"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
TOK=$(printf '%s' "$TOK" | python3 "$ROOT/tools/verification/mfa_fixture.py" --api "$APP")
H=(-H "authorization: Bearer $TOK" -H 'content-type: application/json')
# Separate approver: outreach forbids self-approval by default, so a second
# consultant in the same tenant approves what the admin's agent proposed.
curl -fsS "$APP/api/auth/members" "${H[@]}" -d '{"email":"approver@smoke.example.com","password":"superSecret123!","role":"consultant"}' >/dev/null
TOK2=$(curl -fsS "$APP/api/auth/login" -H 'content-type: application/json' -d '{"email":"approver@smoke.example.com","password":"superSecret123!"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
TOK2=$(printf '%s' "$TOK2" | python3 "$ROOT/tools/verification/mfa_fixture.py" --api "$APP")
H2=(-H "authorization: Bearer $TOK2" -H 'content-type: application/json')
TENANT=$(python3 -c "import jwt,sys,uuid;print(uuid.UUID(jwt.decode('$TOK',options={'verify_signature':False})['tid']))")
# The default tenant policy evaluates contact hours (08–21) in America/Chicago, which made
# this smoke fail every evening. Pin the smoke tenant to a zone where it is ~noon now
# (test-environment setup with the owner identity; every other policy field stays default).
psql -q "$PGURL" -c "INSERT INTO kernel.policy_versions (tenant_id, version, contact_tz) VALUES ('$TENANT', 'smoke-noon', '$NOON_TZ')" >/dev/null
ops() { curl -sS -o "$WORK/out.json" -w '%{http_code}' "${H[@]}" "$@"; }
ops2() { curl -sS -o "$WORK/out.json" -w '%{http_code}' "${H2[@]}" "$@"; }
j() { python3 -c "import json,sys;d=json.load(open('$WORK/out.json'));print(eval(sys.argv[1]))" "$1"; }

log "approver registers a passkey through the kernel ceremony (software authenticator = test equipment)"
SA="$WORK/softauthn.json"; "$BIN/mk-softauthn" new "$SA" es256 >/dev/null
[ "$(ops2 -X POST "$APP/api/agent-ops/approval-credentials/register/begin")" = 200 ] || die "register/begin: $(cat "$WORK/out.json")"
CH=$(j 'd["challenge"]'); [ "$(j 'd["rp_id"]')" = "$RP_ID" ] || die "rp id"
REG=$("$BIN/mk-softauthn" register "$SA" "$CH" "$RP_ID" "$ORIGIN")
[ "$(ops2 -X POST "$APP/api/agent-ops/approval-credentials/register/finish" -d "$REG")" = 201 ] || die "register/finish: $(cat "$WORK/out.json")"
[ "$(j 'd["alg"]')" = ES256 ] || die "credential alg"
# Replaying the same registration bytes must fail: the challenge is single-use.
[ "$(ops2 -X POST "$APP/api/agent-ops/approval-credentials/register/finish" -d "$REG")" = 409 ] || die "registration replay accepted"

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

# Outreach is only proposable for a customer the application knows, with a destination
# timezone (F9) — so every contact in this smoke is a real customer record.
new_customer() { local c; c=$(curl -fsS "$APP/api/customers" "${H[@]}" -d "{\"name\":\"Smoke $1\",\"phone\":\"$2\"}" | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
  curl -fsS "$APP/api/customers/$c/destinations" "${H[@]}" -d "{\"channel\":\"sms\",\"value\":\"$2\"}" >/dev/null
  curl -fsS -X PUT "$APP/api/customers/$c/preferences" "${H[@]}" -d "{\"timezone\":\"$NOON_TZ\"}" >/dev/null
  python3 -c "import uuid;print(uuid.UUID('$c'))"; }
CONTACT=$(new_customer One +15555550100)
CONTACT2=$(new_customer Two +15555550199)
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ); LATER=$(date -u -d '+30 min' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v+30M +%Y-%m-%dT%H:%M:%SZ)
# grant <contact> <destination>: consent is bound to the destination the evidence covers (migration 0007).
grant() { ops -X POST "$APP/api/agent-ops/contacts/$1/permissions" -d "{\"channel\":\"sms\",\"destination\":\"$2\",\"scope\":[\"customer_requested_follow_up\"],\"source\":\"web_form\",\"proof_digest\":\"sha256:$(printf consent-%s "$1" | sha256sum | cut -c1-64)\",\"granted_at\":\"$NOW\",\"expires_at\":\"2027-01-01T00:00:00Z\"}"; }
propose_raw() { # $1 contact $2 to $3 idem
  ops -X POST "$APP/api/agent-ops/actions" -d "{\"origin\":\"agent\",\"request\":{\"workflow\":\"customer_follow_up\",\"action_kind\":\"send_sms\",\"tool_id\":\"mobile.sms.send.v1\",\"resource\":{\"type\":\"contact\",\"id\":\"$1\"},\"arguments\":{\"contact_id\":\"$1\",\"agent_id\":\"moto-1\",\"to\":\"$2\",\"template_id\":\"reorder_followup.v1\",\"rendered_text\":\"Hi! Your order shipped. Reply STOP to opt out.\"},\"purpose\":\"customer_requested_follow_up\",\"risk\":\"high\",\"requested_at\":\"$NOW\",\"expires_at\":\"$LATER\",\"idempotency_key\":\"$3\",\"evidence\":[]}}"; }
propose() { local c; c=$(propose_raw "$@"); case "$c" in 201|202) echo 201;; *) echo "$c";; esac; }
# approve = challenge bound to the action digest → authenticator signs → kernel verifies.
sign_for() { ops2 -X POST "$APP/api/agent-ops/actions/$1/approval-challenge" >/dev/null; "$BIN/mk-softauthn" assert "$SA" "$(j 'd["challenge"]')" "$RP_ID" "$ORIGIN"; }
approve_with() { curl -sS -o "$WORK/out.json" -w '%{http_code}' "${H2[@]}" -X POST "$APP/api/agent-ops/actions/$1/approve" -d "{\"action_digest\":\"$2\",\"reason\":\"smoke\",\"webauthn\":$3}"; }
approve() { local wa; wa=$(sign_for "$1"); approve_with "$1" "$2" "$wa"; }
approve_unbound() { curl -sS -o "$WORK/out.json" -w '%{http_code}' "${H2[@]}" -X POST "$APP/api/agent-ops/actions/$1/approve" -d "{\"action_digest\":\"$2\",\"reason\":\"smoke\"}"; }
state() { ops "$APP/api/agent-ops/actions/$1" >/dev/null; j 'd["state"]'; }

log "gate 2: suppressed contact is refused at proposal"
[ "$(grant "$CONTACT2" +15555550199)" = 201 ] || die "grant2"
[ "$(ops -X POST "$APP/api/agent-ops/suppressions" -d '{"channel":"sms","destination":"+15555550199","reason":"stop","permanent":true,"source":"sms_reply"}')" = 201 ] || die "suppress"
code=$(propose "$CONTACT2" "+15555550199" "smoke-suppressed-1"); [ "$code" = 403 ] || die "suppressed proposal should be 403, got $code: $(cat "$WORK/out.json")"
log "  403 $(j 'd.get("code") or d["decision"]["code"]')"

log "gate 5: idempotent proposal + shared jti"
[ "$(grant "$CONTACT" +15555550100)" = 201 ] || die "grant"
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
# Freeze the worker so approve→revoke is not racing a sub-second dispatch;
# the kernel must then refuse the queued action at dispatch time.
kill -STOP "$WORKER_PID"
[ "$(approve "$A2" "$D2")" = 200 ] || die "approve rev: $(cat "$WORK/out.json")"
AP2=$(j 'd["approval"]["approval_id"]')
[ "$(ops -X POST "$APP/api/agent-ops/approvals/$AP2/revoke")" = 200 ] || die "revoke: $(cat "$WORK/out.json")"
kill -CONT "$WORKER_PID"
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

log "gate 8: approval authority is the human's authenticator, not the proxy's assertion key"
c=$(approve_unbound "$A1" "$D1"); [ "$c" = 403 ] && [ "$(j 'd["code"]')" = WEBAUTHN_REQUIRED ] || die "approval without WebAuthn accepted ($c): $(cat "$WORK/out.json")"
SA2="$WORK/attacker.json"; "$BIN/mk-softauthn" new "$SA2" es256 >/dev/null
ops2 -X POST "$APP/api/agent-ops/actions/$A1/approval-challenge" >/dev/null; CH=$(j 'd["challenge"]')
FORGED=$("$BIN/mk-softauthn" assert "$SA2" "$CH" "$RP_ID" "$ORIGIN")
c=$(approve_with "$A1" "$D1" "$FORGED"); [ "$c" = 403 ] && [ "$(j 'd["code"]')" = WEBAUTHN_CREDENTIAL_MISMATCH ] || die "unregistered authenticator accepted ($c): $(cat "$WORK/out.json")"
# the burned challenge cannot be reused by the real key
REAL=$("$BIN/mk-softauthn" assert "$SA" "$CH" "$RP_ID" "$ORIGIN")
c=$(approve_with "$A1" "$D1" "$REAL"); [ "$c" = 409 ] || die "burned challenge reused ($c)"
# a challenge for A1 cannot approve A3 (digest-bound), and is burned by the attempt
WA1=$(sign_for "$A1")
c=$(approve_with "$A3" "$D3" "$WA1"); [ "$c" = 409 ] || die "transplanted challenge accepted ($c)"
c=$(approve_with "$A1" "$D1" "$WA1"); [ "$c" = 409 ] || die "transplanted-then-reused challenge accepted ($c)"
log "  unbound → 403, unregistered key → 403, burned/transplanted challenge → 409"

log "gate 1: approved action reaches the device agent; signed callback accepted"
[ "$(approve "$A1" "$D1")" = 200 ] || die "approve: $(cat "$WORK/out.json")"
[ "$(j 'd["approval"]["human_binding"]')" = webauthn ] || die "approval not human-bound"
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
MK_DATABASE_URL="$(url_for mk_readonly_login readonly)" "$BIN/mk-audit-verifier" 2>&1 | tee "$WORK/verifier.log" | tail -3

log "gate 7: identities are least-privilege (API cannot claim outbox; relay cannot read approvals; readonly cannot write)"
! psql -q "$(url_for mk_api_login api)" -c "UPDATE kernel.outbox_events SET leased_by='x' WHERE false" >/dev/null 2>&1 || die "api login can touch outbox claims"
! psql -q "$(url_for mk_relay_login relay)" -c "SELECT 1 FROM kernel.approvals LIMIT 1" >/dev/null 2>&1 || die "relay login can read approvals"
! psql -q "$(url_for mk_readonly_login readonly)" -c "INSERT INTO kernel.kill_switches (scope,tenant_id,dispatch_enabled,changed_by) VALUES ('tenant','$TENANT',false,'x')" >/dev/null 2>&1 || die "readonly login can write"
! psql -q "$(url_for mk_api_login api)" -c "DELETE FROM kernel.audit_events WHERE false" >/dev/null 2>&1 || die "api login can delete audit"

log "worker log clean under its restricted login (housekeeping under mk_kernel_worker is proven by mk-store::postgres::worker_role_can_discover_tenants_and_purge_nonces_across_tenants)"
! grep -qE "tenant listing failed|housekeeping failed|permission denied" "$WORK/worker.log" || die "worker housekeeping failed under mk_worker_login"

log "gate 9: session revocation blocks the approver's next request and any live approval"
[ "$(propose "$CONTACT" "+15555550100" "smoke-revocation-1")" = 201 ] || die "propose revocation"
A4=$(j 'd["result"]["action_id"]'); D4=$(j 'd["result"]["action_digest"]')
# Freeze before approval so a fast worker cannot dispatch before the test's revoke.
kill -STOP "${PIDS[2]}" 2>/dev/null || true
[ "$(approve "$A4" "$D4")" = 200 ] || die "approve A4: $(cat "$WORK/out.json")"
[ "$(ops2 -X POST "$APP/api/agent-ops/revocations" -d '{"reason":"smoke: lost phone"}')" = 201 ] || die "revocation: $(cat "$WORK/out.json")"
kill -CONT "${PIDS[2]}" 2>/dev/null || true
c=$(ops2 "$APP/api/agent-ops/approvals/pending")
[ "$c" = 401 ] || die "revoked session still accepted ($c)"
# Revoked sessions are rejected at the app boundary before minting an assertion.
[ "$(j 'd.get("detail")')" = 'Session expired or revoked' ] || die "unexpected app revocation error"
sleep 3; s=$(state "$A4"); case "$s" in cancelled) ;; *) die "approval by revoked session still dispatched: $s";; esac
grep -q "$A4" "$WORK/agent.log" && die "revoked-approver action reached the device agent"
log "  revoked session → 401 PRINCIPAL_REVOKED; its live approval → cancelled"

log "gate 10: production SMS path — registered sender, provider submission, authenticated status callbacks, inbound STOP"
[ "$(ops -X POST "$APP/api/agent-ops/senders" -d "{\"owner_user_id\":\"$(python3 -c "import jwt,uuid;print(uuid.UUID(jwt.decode('$TOK',options={'verify_signature':False})['sub']))")\",\"display_name\":\"Smoke Business\",\"account_sid\":\"$TW_ACCOUNT\",\"auth_token\":\"$TW_TOKEN\",\"from_number\":\"+15005550006\"}")" = 201 ] || die "register sender: $(cat "$WORK/out.json")"
SENDER=$(j 'd["sender_identity_id"]')
# Secrets never reach FastAPI storage; the kernel sealed the token.
! grep -q "$TW_TOKEN" "$WORK/app.db" 2>/dev/null || die "provider token found in the application database"
! grep -q "$TW_TOKEN" "$WORK/api.log" "$WORK/worker.log" "$WORK/app.log" || die "provider token leaked to logs"
# Third approver (the earlier one's session is revoked): register a passkey.
curl -fsS "$APP/api/auth/members" "${H[@]}" -d '{"email":"approver3@smoke.example.com","password":"superSecret123!","role":"consultant"}' >/dev/null
TOK3=$(curl -fsS "$APP/api/auth/login" -H 'content-type: application/json' -d '{"email":"approver3@smoke.example.com","password":"superSecret123!"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
TOK3=$(printf '%s' "$TOK3" | python3 "$ROOT/tools/verification/mfa_fixture.py" --api "$APP")
H2=(-H "authorization: Bearer $TOK3" -H 'content-type: application/json')
SA="$WORK/softauthn3.json"; "$BIN/mk-softauthn" new "$SA" es256 >/dev/null
[ "$(ops2 -X POST "$APP/api/agent-ops/approval-credentials/register/begin")" = 200 ] || die "register/begin 3"
REG=$("$BIN/mk-softauthn" register "$SA" "$(j 'd["challenge"]')" "$RP_ID" "$ORIGIN")
[ "$(ops2 -X POST "$APP/api/agent-ops/approval-credentials/register/finish" -d "$REG")" = 201 ] || die "register/finish 3"
# C8: dispatch is deferred until the inbound path has a successful check.
for i in $(seq 1 40); do
  ops "$APP/api/agent-ops/inbound/health" >/dev/null
  [ "$(j 'd.get("dispatch_blocked", "unverified") is None')" = True ] && break
  sleep 0.5
done
[ "$(j 'd.get("dispatch_blocked", "unverified") is None')" = True ] || die "no committed public inbound probe"
CONTACT3=$(python3 -c 'import uuid;print(uuid.uuid4())')
# The application customer record (timezone known → F9 passes; contact tz travels to the kernel).
CUST=$(curl -fsS "$APP/api/customers" "${H[@]}" -d '{"name":"Smoke Customer","phone":"+15555550123"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
curl -fsS "$APP/api/customers/$CUST/destinations" "${H[@]}" -d '{"channel":"sms","value":"+15555550123"}' >/dev/null
curl -fsS -X PUT "$APP/api/customers/$CUST/preferences" "${H[@]}" -d "{\"timezone\":\"$NOON_TZ\"}" >/dev/null
CONTACT3=$(python3 -c "import uuid;print(uuid.UUID('$CUST'))")
[ "$(grant "$CONTACT3" +15555550123)" = 201 ] || die "grant3"
propose_provider() { ops -X POST "$APP/api/agent-ops/actions" -d "{\"origin\":\"agent\",\"request\":{\"workflow\":\"customer_follow_up\",\"action_kind\":\"send_sms\",\"tool_id\":\"sms.provider.send.v1\",\"resource\":{\"type\":\"contact\",\"id\":\"$CONTACT3\"},\"arguments\":{\"contact_id\":\"$CONTACT3\",\"to\":\"+15555550123\",\"template_id\":\"reorder_followup.v1\",\"rendered_text\":\"$1 Reply STOP to opt out.\"},\"purpose\":\"customer_requested_follow_up\",\"risk\":\"high\",\"requested_at\":\"$NOW\",\"expires_at\":\"$LATER\",\"idempotency_key\":\"$2\",\"evidence\":[]}}"; }
c=$(propose_provider "Hi! Your order shipped." "smoke-provider-1"); [ "$c" = 202 ] || die "propose provider ($c): $(cat "$WORK/out.json")"
A5=$(j 'd["result"]["action_id"]'); D5=$(j 'd["result"]["action_digest"]')
[ "$(j 'd["result"]["message_state"]')" = awaiting_approval ] || die "message_state at proposal"
[ "$(approve "$A5" "$D5")" = 200 ] || die "approve provider: $(cat "$WORK/out.json")"
for i in $(seq 1 40); do ops "$APP/api/agent-ops/actions/$A5" >/dev/null; ms=$(j 'd.get("message_state")'); [ "$ms" = delivered ] && break; sleep 1; done
[ "$ms" = delivered ] || die "provider path did not reach delivered via authenticated callbacks: $(cat "$WORK/out.json")"
[ "$(j 'd["state"]')" = completed ] && [ "$(j 'd["read_status"]')" = unknown ] || die "state/read_status"
[ "$(j 'd["provider_message_id"]')" != None ] || die "no provider message id"
grep -q "callback sent for .* → 200" "$WORK/twsim.log" && grep -q "callback delivered for .* → 200" "$WORK/twsim.log" || die "simulator callbacks not accepted"
# Forged status callback (bad signature, hostile forwarding headers) → 403.
c=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$API/webhooks/twilio/status/$SENDER" -H 'x-twilio-signature: AAAA' -H 'x-forwarded-host: attacker.example' -d "MessageSid=SMforged&MessageStatus=delivered&AccountSid=$TW_ACCOUNT")
[ "$c" = 403 ] || die "forged callback accepted ($c)"
# Inbound STOP, signed exactly as Twilio would over the configured public URL → suppression; next proposal refused.
python3 - "$TW_TOKEN" "$WEBHOOK_BASE/webhooks/twilio/inbound/$SENDER" "$API/webhooks/twilio/inbound/$SENDER" "$TW_ACCOUNT" <<'EOF2'
import sys,hmac,hashlib,base64,urllib.request,urllib.parse
token,public,deliver,acct=sys.argv[1:]
form=[("MessageSid","SMsmokestop1"),("AccountSid",acct),("From","+15555550123"),("To","+15005550006"),("Body","STOP"),("NumMedia","0")]
data=public+"".join(k+v for k,v in sorted(form))
sig=base64.b64encode(hmac.new(token.encode(),data.encode(),hashlib.sha1).digest()).decode()
req=urllib.request.Request(deliver,data=urllib.parse.urlencode(form).encode(),headers={"X-Twilio-Signature":sig,"Content-Type":"application/x-www-form-urlencoded"})
r=urllib.request.urlopen(req); assert r.status==200, r.status
# duplicate delivery
r=urllib.request.urlopen(req); assert r.status==200
EOF2
c=$(propose_provider "One more." "smoke-provider-2"); [ "$c" = 403 ] && [ "$(j 'd["decision"]["code"]')" = suppressed ] || die "opted-out customer still proposable ($c)"
# Application-side meaning processing records the opt-out outcome exactly once.
[ "$(ops -X POST "$APP/api/inbound/process" -d '{"limit":50}')" = 200 ] || die "inbound process: $(cat "$WORK/out.json")"
[ "$(j 'd["processed"]')" = 1 ] && [ "$(j 'd["events"][0]["class"]')" = opt_out ] || die "inbound processing: $(cat "$WORK/out.json")"
[ "$(ops -X POST "$APP/api/inbound/process" -d '{"limit":50}')" = 200 ] && [ "$(j 'd["processed"]')" = 0 ] || die "inbound event processed twice"
log "  provider_accepted → sent → delivered via signed callbacks; forged → 403; STOP → suppressed, proposal refused, processed once"

log "gate 11: envelope key rotation under load of real rows, then the restore gate (report mode)"
# Operator path with the owner identity: rotate → re-seal → retire; services restart on the new ring.
"$BIN/mk-keyctl" status >"$WORK/keyctl.log" 2>&1 || die "keyctl status"
grep -q "current_version=1 " "$WORK/keyctl.log" || die "expected version 1 active: $(cat "$WORK/keyctl.log")"
"$BIN/mk-keyctl" rotate "smoke" >>"$WORK/keyctl.log" 2>&1 || die "keyctl rotate"
"$BIN/mk-keyctl" reencrypt >>"$WORK/keyctl.log" 2>&1 || die "keyctl reencrypt"
grep -q "unreadable (foreign/lost key material, left untouched): 0" "$WORK/keyctl.log" || die "reencrypt reported unreadable rows: $(cat "$WORK/keyctl.log")"
"$BIN/mk-keyctl" retire 1 >>"$WORK/keyctl.log" 2>&1 || die "keyctl retire 1: $(cat "$WORK/keyctl.log")"
pkill -f "[m]k-action-api" || true; pkill -f "[m]k-action-worker" || true; sleep 1
MK_DATABASE_URL="$(url_for mk_api_login api)" MK_BIND=127.0.0.1:8090 RUST_ACTION_KERNEL_ENABLED=1 \
  MK_APPROVAL_RP_ID="$RP_ID" MK_APPROVAL_ORIGINS="$ORIGIN" MK_PUBLIC_WEBHOOK_BASE="$WEBHOOK_BASE" \
  "$BIN/mk-action-api" >>"$WORK/api.log" 2>&1 & PIDS+=($!)
MK_DATABASE_URL="$(url_for mk_worker_login worker)" MK_WORKER_ID=worker-smoke MK_LEASE_SECS=60 MK_ALLOW_LOOPBACK_HTTP=1 \
  MK_MOBILE_INTAKE_URL="$AGENT/work-orders" MK_EGRESS_AUTHORITIES=127.0.0.1:8787,127.0.0.1:8790,127.0.0.1:8090 \
  MK_TWILIO_API_BASE="$TWSIM" MK_PUBLIC_WEBHOOK_BASE="$WEBHOOK_BASE" \
  "$BIN/mk-action-worker" >>"$WORK/worker.log" 2>&1 & PIDS+=($!)
for i in $(seq 1 30); do curl -fsS "$API/health/ready" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS "$API/health/ready" >/dev/null || die "kernel api not ready after rotation"
# The re-sealed sender credential must still authenticate a provider webhook (new SID, benign text → held for meaning).
python3 - "$TW_TOKEN" "$WEBHOOK_BASE/webhooks/twilio/inbound/$SENDER" "$API/webhooks/twilio/inbound/$SENDER" "$TW_ACCOUNT" <<'EOF2'
import sys,hmac,hashlib,base64,urllib.request,urllib.parse
token,public,deliver,acct=sys.argv[1:]
form=[("MessageSid","SMsmokerotated1"),("AccountSid",acct),("From","+15555550777"),("To","+15005550006"),("Body","Thanks, see you Thursday"),("NumMedia","0")]
data=public+"".join(k+v for k,v in sorted(form))
sig=base64.b64encode(hmac.new(token.encode(),data.encode(),hashlib.sha1).digest()).decode()
req=urllib.request.Request(deliver,data=urllib.parse.urlencode(form).encode(),headers={"X-Twilio-Signature":sig,"Content-Type":"application/x-www-form-urlencoded"})
r=urllib.request.urlopen(req); assert r.status==200, r.status
EOF2
[ "$(ops -X POST "$APP/api/inbound/process" -d '{"limit":50}')" = 200 ] && [ "$(j 'd["processed"]')" = 1 ] || die "inbound body unreadable after rotation: $(cat "$WORK/out.json")"
# A new provider send still works end to end under the rotated key (the worker unseals the sender token).
CUST2=$(curl -fsS "$APP/api/customers" "${H[@]}" -d '{"name":"Smoke Customer Two","phone":"+15555550124"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
curl -fsS "$APP/api/customers/$CUST2/destinations" "${H[@]}" -d '{"channel":"sms","value":"+15555550124"}' >/dev/null
curl -fsS -X PUT "$APP/api/customers/$CUST2/preferences" "${H[@]}" -d "{\"timezone\":\"$NOON_TZ\"}" >/dev/null
CONTACT4=$(python3 -c "import uuid;print(uuid.UUID('$CUST2'))"); [ "$(grant "$CONTACT4" +15555550124)" = 201 ] || die "grant4"
c=$(ops -X POST "$APP/api/agent-ops/actions" -d "{\"origin\":\"agent\",\"request\":{\"workflow\":\"customer_follow_up\",\"action_kind\":\"send_sms\",\"tool_id\":\"sms.provider.send.v1\",\"resource\":{\"type\":\"contact\",\"id\":\"$CONTACT4\"},\"arguments\":{\"contact_id\":\"$CONTACT4\",\"to\":\"+15555550124\",\"template_id\":\"reorder_followup.v1\",\"rendered_text\":\"Hi! Your refill is ready. Reply STOP to opt out.\"},\"purpose\":\"customer_requested_follow_up\",\"risk\":\"high\",\"requested_at\":\"$NOW\",\"expires_at\":\"$LATER\",\"idempotency_key\":\"smoke-provider-rotated\",\"evidence\":[]}}")
[ "$c" = 202 ] || die "propose after rotation ($c): $(cat "$WORK/out.json")"
A6=$(j 'd["result"]["action_id"]'); D6=$(j 'd["result"]["action_digest"]')
[ "$(approve "$A6" "$D6")" = 200 ] || die "approve after rotation: $(cat "$WORK/out.json")"
for i in $(seq 1 40); do ops "$APP/api/agent-ops/actions/$A6" >/dev/null; ms=$(j 'd.get("message_state")'); [ "$ms" = delivered ] && break; sleep 1; done
[ "$ms" = delivered ] || die "provider path broken after key rotation: $(cat "$WORK/out.json")"
# Restore gate in report mode on the live database: must FAIL (dispatch is enabled) while every
# recoverability check passes — it never enables anything.
set +e; "$BIN/mk-restore-gate" --inspection-only --restored-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$WORK/restore-gate.json" 2>"$WORK/restore-gate.err"; rc=$?; set -e
[ "$rc" = 1 ] || die "restore gate must refuse while dispatch is enabled (rc=$rc): $(cat "$WORK/restore-gate.json" "$WORK/restore-gate.err")"
python3 - "$WORK/restore-gate.json" <<'EOF2'
import json,sys
rows=[json.loads(l) for l in open(sys.argv[1]) if l.strip()]
checks={r["check"]:r for r in rows if "check" in r}
assert checks["global_dispatch_disabled"]["ok"] is False, checks["global_dispatch_disabled"]
for c in ("keyring_loads","audit_chain_verified","suppression_ledger_loaded","credentials_unseal"):
    assert checks[c]["ok"] is True, checks[c]
assert checks["credentials_unseal"]["detail"]["unreadable"]==0
assert checks["keyring_loads"]["detail"]["current"]==2, checks["keyring_loads"]
assert [r for r in rows if r.get("gate")=="FAIL"], rows[-1]
EOF2
log "  v1 → v2 rotated, re-sealed, v1 retired; webhooks/sends still authenticate; restore gate reports FAIL-while-enabled with all recoverability checks green"

log "no PII in kernel/agent logs"
! grep -q "5555550100\|5555550123\|Your order shipped" "$WORK/api.log" "$WORK/worker.log" "$WORK/relay.log" "$WORK/agent.log" || die "PII leaked to logs"

log "gate 8: production pre-flight passes against this stack (and refuses --for-enable without an acceptance record)"
export KERNEL_URL="$API" APP_URL="$APP" PG_HOST="${HOSTDB%/*}" PG_DB="${HOSTDB##*/}" PG_ADMIN_URL="$PGURL" \
  MK_DB_API_PASSWORD="api-$PW" MK_DB_WORKER_PASSWORD="worker-$PW" MK_DB_RELAY_PASSWORD="relay-$PW" MK_DB_READONLY_PASSWORD="readonly-$PW" \
  MK_PREFLIGHT_ACCESS_TOKEN="$TOK" \
  MK_AUDIT_VERIFIER="$BIN/mk-audit-verifier" MK_EGRESS_AUTHORITIES=127.0.0.1:8787 MK_MOBILE_INTAKE_URL="https://127.0.0.1:8787/work-orders"
bash "$ROOT/scripts/kernel-preflight.sh" > "$WORK/preflight.log" 2>&1 || { cat "$WORK/preflight.log"; die "pre-flight failed"; }
grep -E "passed, 0 failed" "$WORK/preflight.log" >/dev/null || { cat "$WORK/preflight.log"; die "pre-flight"; }
if MK_ACCEPTANCE_RECORD="$WORK/no-such-record.md" bash "$ROOT/scripts/kernel-preflight.sh" --for-enable > "$WORK/preflight-enable.log" 2>&1; then
  die "pre-flight --for-enable must fail without an acceptance record"; fi
grep -q "no real-device acceptance record" "$WORK/preflight-enable.log" || die "pre-flight --for-enable gave the wrong reason"
# A verbatim copy of the template (placeholders) must be rejected (Codex P1 on #32).
if MK_ACCEPTANCE_RECORD="$ROOT/deploy/kernel/ACCEPTANCE.template.md" bash "$ROOT/scripts/kernel-preflight.sh" --for-enable > "$WORK/preflight-template.log" 2>&1; then
  die "pre-flight --for-enable accepted the unfilled template"; fi
grep -q "placeholder" "$WORK/preflight-template.log" || die "template rejection gave the wrong reason: $(grep FAIL "$WORK/preflight-template.log")"
# A fully filled record passes; the same record with Result: REJECTED does not.
EVHEAD=$(python3 -c "import json;print(json.loads(open('$WORK/evidence/evidence-ledger.jsonl').read().splitlines()[-1])['entry_hash'])")
AROOT=$(grep -o 'sha256:[0-9a-f]\{64\}' "$WORK/verifier.log" 2>/dev/null | tail -1); [ -n "$AROOT" ] || AROOT="sha256:$(printf x | sha256sum | cut -c1-64)"
cat > "$WORK/ACCEPTANCE.md" <<REC
Date: 2026-10-20 12:00 America/Chicago
Device: Moto G Power, serial digest sha256:$(printf serial | sha256sum | cut -c1-64)
Android: 14 / motorola/x
Kernel commit: $(git -C "$ROOT" rev-parse HEAD)
Agent commit: $(git -C "$ROOT" rev-parse HEAD)
Destination: controlled test phone (never a customer number)
Task id: $TID
Evidence chain head: $EVHEAD
Audit root: $AROOT
Negative runs: revoke-before-dispatch = yes; tenant kill switch = yes
Reviewer: smoke harness — looked at $TID.png and the receiving phone
Result: ACCEPTED
REC
# This dev stack is NOT production-configured, and --for-enable reads what the
# RUNNING kernel enforces (its readiness report), so it must refuse — naming the
# controls this stack lacks — however the shell is dressed up. Exporting
# production-looking values into the pre-flight shell must change nothing.
printf 'smoke CA placeholder\n' > "$WORK/ca.pem"
for envset in "" "MK_LEGACY_SEAL_RETIRED=1 MK_PUBLIC_WEBHOOK_BASE=https://hooks.smoke.invalid MK_DB_SSLROOTCERT=$WORK/ca.pem MK_TWILIO_API_BASE=https://api.twilio.com"; do
  if env $envset MK_ACCEPTANCE_RECORD="$WORK/ACCEPTANCE.md" MK_KEYCTL="$BIN/mk-keyctl" MK_RESTORE_GATE="$BIN/mk-restore-gate" \
      bash "$ROOT/scripts/kernel-preflight.sh" --for-enable > "$WORK/preflight-devenv.log" 2>&1; then
    die "pre-flight --for-enable accepted a development kernel (shell: ${envset:-plain})"; fi
  for why in "legacy seal version 0" "WEBHOOK_BASE is not https"; do
    grep "FAIL" "$WORK/preflight-devenv.log" | grep -q "$why" || { cat "$WORK/preflight-devenv.log"; die "pre-flight --for-enable did not name: $why"; }; done
  # The parts this stack CAN satisfy pass: the record, fingerprints, restore gate.
  for good in "real-device acceptance record complete" "fingerprint keys match the running kernel" "kernel enforces passkey-bound approvals" "live recovery inspection passes"; do
    grep "PASS" "$WORK/preflight-devenv.log" | grep -q "$good" || { cat "$WORK/preflight-devenv.log"; die "pre-flight --for-enable failed: $good"; }; done
done
sed -i 's/^Result: ACCEPTED$/Result: REJECTED (screenshot missing)/' "$WORK/ACCEPTANCE.md"
MK_ACCEPTANCE_RECORD="$WORK/ACCEPTANCE.md" MK_KEYCTL="$BIN/mk-keyctl" MK_RESTORE_GATE="$BIN/mk-restore-gate" \
  bash "$ROOT/scripts/kernel-preflight.sh" --for-enable > "$WORK/preflight-rejected.log" 2>&1 || true
grep "FAIL" "$WORK/preflight-rejected.log" | grep -q "acceptance record rejected" || die "pre-flight --for-enable accepted a REJECTED record"
log "  $(grep -E 'passed, . failed' "$WORK/preflight.log")"

log "ALL GATES PASSED — artifacts in $WORK"
