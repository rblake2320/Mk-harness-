#!/usr/bin/env bash
# Production pre-flight for the MK action kernel. Run against a DEPLOYED stack
# (staging or prod) before anyone sets RUST_ACTION_KERNEL_ENABLED=1, and again
# after every deploy. Read-only except for one login that mints a session.
#
#   KERNEL_URL=http://kernel-api:8090 APP_URL=https://app.example \
#   PG_HOST=db PG_DB=mkharness PG_ADMIN_URL=postgres://mk:…@db/mkharness \
#   MK_DB_API_PASSWORD=… MK_DB_WORKER_PASSWORD=… MK_DB_RELAY_PASSWORD=… MK_DB_READONLY_PASSWORD=… \
#   MK_PREFLIGHT_EMAIL=ops@example MK_PREFLIGHT_PASSWORD=… \
#   scripts/kernel-preflight.sh [--for-enable]
#
# --for-enable additionally requires production approval/key/TLS configuration, a
#   passing restore gate in report mode, and the real-device acceptance record
# (deploy/kernel/ACCEPTANCE.md or $MK_ACCEPTANCE_RECORD) to be complete.
# Exit 0 = every check passed. Any failure exits 1 with the failing check named.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FOR_ENABLE=0; [ "${1:-}" = "--for-enable" ] && FOR_ENABLE=1
: "${KERNEL_URL:?}" "${APP_URL:?}" "${PG_HOST:?}" "${PG_DB:?}" "${PG_ADMIN_URL:?}"
: "${MK_DB_API_PASSWORD:?}" "${MK_DB_WORKER_PASSWORD:?}" "${MK_DB_RELAY_PASSWORD:?}" "${MK_DB_READONLY_PASSWORD:?}"
: "${MK_PREFLIGHT_EMAIL:?}" "${MK_PREFLIGHT_PASSWORD:?}"
VERIFIER="${MK_AUDIT_VERIFIER:-$ROOT/rust/target/release/mk-audit-verifier}"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$*"; }
check() { local name=$1; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else fail "$name"; fi; }
url_for() { echo "postgres://$1:$2@$PG_HOST/$PG_DB"; }
API_URL=$(url_for mk_api_login "$MK_DB_API_PASSWORD")
WORKER_URL=$(url_for mk_worker_login "$MK_DB_WORKER_PASSWORD")
RELAY_URL=$(url_for mk_relay_login "$MK_DB_RELAY_PASSWORD")
RO_URL=$(url_for mk_readonly_login "$MK_DB_READONLY_PASSWORD")
q() { psql -qtAX "$1" -c "$2" 2>/dev/null; }
# predicates (functions, so `check` can call them without re-quoting)
http_is() { local code=$1; shift; [ "$(curl -s -o /dev/null -w '%{http_code}' "$@")" = "$code" ]; }
q_eq()   { [ "$(q "$1" "$2")" = "$3" ]; }           # query result equals
q_fails(){ ! q "$1" "$2" >/dev/null 2>&1 && ! psql -qtAX "$1" -c "$2" >/dev/null 2>&1; }  # statement is refused

echo "== 1. liveness"
check "kernel /health/ready is 200"      http_is 200 "$KERNEL_URL/health/ready"
metrics_ok() { curl -fsS "$KERNEL_URL/metrics" | grep -q mk_; }
check "kernel /metrics served"           metrics_ok
check "kernel internal API not reachable without assertion (401)" http_is 401 "$KERNEL_URL/internal/v1/approvals/pending"

echo "== 2. FastAPI ↔ kernel assertion pairing"
TOK=$(curl -fsS "$APP_URL/api/auth/login" -H 'content-type: application/json' \
  -d "{\"email\":\"$MK_PREFLIGHT_EMAIL\",\"password\":\"$MK_PREFLIGHT_PASSWORD\"}" 2>/dev/null \
  | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null)
if [ -z "$TOK" ]; then fail "app login for pre-flight user"; else ok "app login"; fi
H=(-H "authorization: Bearer $TOK")
check "app → kernel health 200 (kernel configured in app)"          http_is 200 "${H[@]}" "$APP_URL/api/agent-ops/health"
check "app-minted assertion accepted by kernel (GET pending → 200)"  http_is 200 "${H[@]}" "$APP_URL/api/agent-ops/approvals/pending"
check "app never falls back: bogus action id → kernel 404, not 200"  http_is 404 "${H[@]}" "$APP_URL/api/agent-ops/actions/00000000-0000-7000-8000-000000000000"

echo "== 3. schema at head"
want=$(ls "$ROOT/migrations/kernel"/*.sql | wc -l | tr -d ' ')
have=$(q "$PG_ADMIN_URL" "SELECT count(*) FROM _sqlx_migrations WHERE success")
[ "$have" = "$want" ] && ok "migrations applied: $have/$want" || fail "migrations applied: ${have:-?}/$want"
check "no failed migration rows" q_eq "$PG_ADMIN_URL" "SELECT count(*) FROM _sqlx_migrations WHERE NOT success" 0

echo "== 4. per-process identities (least privilege, RLS enforced)"
for pair in "mk_api_login:mk_kernel_api" "mk_worker_login:mk_kernel_worker" "mk_relay_login:mk_kernel_relay" "mk_readonly_login:mk_kernel_readonly"; do
  login=${pair%%:*}; priv=${pair##*:}
  roles=$(q "$PG_ADMIN_URL" "SELECT string_agg(p.rolname,',') FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member JOIN pg_roles p ON p.oid=m.roleid WHERE r.rolname='$login'")
  flags=$(q "$PG_ADMIN_URL" "SELECT rolsuper||','||rolbypassrls||','||rolcreaterole||','||rolcreatedb FROM pg_roles WHERE rolname='$login'")
  [ "$roles" = "$priv" ] && [ "$flags" = "false,false,false,false" ] && ok "$login → exactly $priv; no superuser/bypassrls" || fail "$login roles=[$roles] flags=[$flags]"
done
check "api cannot claim outbox rows"        q_fails "$API_URL" "UPDATE kernel.outbox_events SET leased_by='x' WHERE false"
check "api cannot delete audit events"      q_fails "$API_URL" "DELETE FROM kernel.audit_events WHERE false"
check "api cannot delete assertion jtis"    q_fails "$API_URL" "DELETE FROM kernel.assertion_jtis WHERE false"
check "relay cannot read approvals"         q_fails "$RELAY_URL" "SELECT 1 FROM kernel.approvals LIMIT 1"
check "relay cannot read actions payloads"  q_fails "$RELAY_URL" "SELECT 1 FROM kernel.actions LIMIT 1"
check "readonly cannot write kill switches" q_fails "$RO_URL" "INSERT INTO kernel.kill_switches (scope,tenant_id,dispatch_enabled,changed_by) VALUES ('global',NULL,false,'x')"
check "worker can discover tenants (RLS policy present)" q_eq "$PG_ADMIN_URL" "SELECT count(*) FROM pg_policy WHERE polname='worker_tenant_discovery'" 1
# Every table that carries a tenant_id column must have RLS ENABLED *and* FORCED
# (the migration's list); assertion_jtis, kill_switches and tenant_directory
# (tenant UUIDs only, for cross-tenant operator enumeration — 0009) are the only
# intentional exceptions. Counting "enabled but not forced" alone would pass a
# table where RLS was disabled outright.
rls_ok() {
  local bad
  bad=$(q "$PG_ADMIN_URL" "SELECT string_agg(c.relname, ',') FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
          JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped
         WHERE n.nspname = 'kernel' AND c.relkind = 'r'
           AND c.relname NOT IN ('assertion_jtis','kill_switches','tenant_directory')
           AND NOT (c.relrowsecurity AND c.relforcerowsecurity)")
  [ -z "$bad" ] || { echo "    tables without enabled+forced RLS: $bad" >&2; return 1; }
  # and the list is non-trivial (schema present)
  [ "$(q "$PG_ADMIN_URL" "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='kernel' AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity")" -ge 16 ]
}
check "RLS enabled AND forced on every tenant-scoped table (16+)" rls_ok
check "tenant_directory holds tenant ids only (no tenant data outside RLS)" q_eq "$PG_ADMIN_URL" "SELECT string_agg(attname, ',' ORDER BY attname) FROM pg_attribute WHERE attrelid = 'kernel.tenant_directory'::regclass AND attnum > 0 AND NOT attisdropped" "first_seen,tenant_id"
check "no runtime login owns kernel tables" q_eq "$PG_ADMIN_URL" "SELECT count(*) FROM pg_tables WHERE schemaname='kernel' AND tableowner LIKE 'mk_%login'" 0

echo "== 5. kill switches"
g=$(q "$RO_URL" "SELECT dispatch_enabled FROM kernel.kill_switches WHERE scope='global'")
[ -n "$g" ] && ok "global kill switch row present (dispatch_enabled=$g)" || fail "global kill switch row missing (worker fails closed, but fix it)"
echo "     tenant switches off: $(q "$RO_URL" "SELECT count(*) FROM kernel.kill_switches WHERE scope='tenant' AND NOT dispatch_enabled")"

echo "== 6. audit chain"
if [ -x "$VERIFIER" ]; then
  out=$(MK_DATABASE_URL="$RO_URL" "$VERIFIER" 2>&1)
  if grep -q '"chain ok"' <<<"$out" || [ "$(q "$RO_URL" 'SELECT count(*) FROM kernel.audit_heads')" = 0 ]; then
    grep -qiE 'broken|mismatch|error' <<<"$out" && fail "audit chain: $(grep -iE 'broken|mismatch|error' <<<"$out" | head -1)" || ok "audit chain verifies for every tenant (read-only identity)"
  else fail "audit verifier produced no result"; fi
else fail "mk-audit-verifier not found at $VERIFIER (set MK_AUDIT_VERIFIER)"; fi

echo "== 7. configuration hygiene"
COMPOSE="$ROOT/docker-compose.kernel.yml"
compose_check() { python3 -c "
import yaml,sys
d=yaml.safe_load(open('$COMPOSE'))['services']
k=[n for n in d if n.startswith('kernel-')]
assert not [n for n in k if 'KERNEL_ASSERTION_PRIVATE_KEY' in str(d[n].get('environment',{}))], 'private key in kernel service'
assert not d['kernel-api'].get('ports'), 'kernel-api publishes ports'
for n in ('kernel-api','kernel-relay','kernel-worker','kernel-verifier'):
    s=d[n]; assert s.get('read_only') is True and s.get('cap_drop')==['ALL'] and 'no-new-privileges:true' in s.get('security_opt',[]), n+' not hardened'
assert 'MK_MASTER_KEY' not in str(d['kernel-verifier'].get('environment',{})), 'verifier holds master key'
"; }
check "compose: no private key in kernel services, no published kernel ports, all hardened, verifier keyless" compose_check
[ -n "${MK_EGRESS_AUTHORITIES:-}" ] && ok "MK_EGRESS_AUTHORITIES set ($MK_EGRESS_AUTHORITIES)" || fail "MK_EGRESS_AUTHORITIES unset — worker cannot reach any adapter"
case "${MK_MOBILE_INTAKE_URL:-}" in https://*) ok "MK_MOBILE_INTAKE_URL is https";; "") fail "MK_MOBILE_INTAKE_URL unset";; *) fail "MK_MOBILE_INTAKE_URL must be https (got ${MK_MOBILE_INTAKE_URL%%:*})";; esac

echo "== 8. enable gate"
WORKDIR_PROBLEMS=$(mktemp); trap 'rm -f "$WORKDIR_PROBLEMS"' EXIT
if [ "$FOR_ENABLE" = 1 ]; then
  # What the RUNNING kernel enforces (its readiness report), not what this shell
  # claims: approval binding, user verification, keyring, fingerprint kids.
  EFF=$(curl -fsS "$KERNEL_URL/health/ready" 2>/dev/null || echo '{}')
  eff() { printf '%s' "$EFF" | python3 -c "import json,sys;d=json.load(sys.stdin).get('effective',{});v=d.get('$1');print(json.dumps(v) if not isinstance(v,str) else v)"; }
  [ "$(eff approval_binding)" = webauthn ] && ok "kernel enforces passkey-bound approvals" \
    || fail "kernel approval binding is '$(eff approval_binding)' — set MK_APPROVAL_RP_ID/ORIGINS, never MK_ALLOW_UNBOUND_APPROVAL"
  [ "$(eff approval_require_uv)" = true ] && ok "kernel requires user verification on approvals" || fail "kernel accepts approvals without user verification (MK_APPROVAL_ALLOW_NO_UV)"
  [ "$(eff legacy_seal_accepted)" = false ] && ok "kernel no longer accepts legacy master-key ciphertext" \
    || fail "kernel still loads legacy seal version 0 (reencrypt, retire 0, set MK_LEGACY_SEAL_RETIRED=1, restart)"
  cur=$(eff current_key_version); [ -n "$cur" ] && [ "$cur" != 0 ] && [ "$cur" != null ] && ok "kernel seals under KEK-wrapped version $cur" \
    || fail "kernel seals with the bare master key (MK_KEK unset)"
  kv=$(q "$RO_URL" "SELECT count(*) FROM kernel.key_versions WHERE status='active'")
  [ "$kv" = 1 ] && ok "one active key version" || fail "active key versions: ${kv:-?} (run mk-keyctl rotate initial)"
  [ "$(eff public_webhook_base_https)" = true ] && ok "kernel webhook base is https" || fail "kernel MK_PUBLIC_WEBHOOK_BASE is not https"
  # Not observable from the kernel API; checked against the env file the tasks receive.
  case "${MK_DB_SSLROOTCERT:-}" in "") fail "MK_DB_SSLROOTCERT unset — database TLS would not be verify-full against the RDS CA";; *) [ -r "$MK_DB_SSLROOTCERT" ] && ok "MK_DB_SSLROOTCERT present" || fail "MK_DB_SSLROOTCERT not readable: $MK_DB_SSLROOTCERT";; esac
  [ "${MK_TWILIO_API_BASE:-}" = "https://api.twilio.com" ] && ok "worker MK_TWILIO_API_BASE is the live provider" || fail "MK_TWILIO_API_BASE is '${MK_TWILIO_API_BASE:-}' — production must point at the live provider, staging must not enable dispatch"
  # Destination fingerprints (migrations 0008/0009): every tenant's rows checked
  # inside that tenant's transaction (RLS-safe), with the kids the kernel runs.
  KC="${MK_KEYCTL:-$ROOT/rust/target/release/mk-keyctl}"
  if [ -x "$KC" ]; then
    kids_json=$(eff fingerprint_kids)
    if MK_DATABASE_URL="$RO_URL" "$KC" fingerprint-status >"$WORKDIR_PROBLEMS.fp" 2>&1; then
      grep -q "current_kid=$(printf '%s' "$kids_json" | python3 -c 'import json,sys;print(json.load(sys.stdin)[0])' 2>/dev/null)" "$WORKDIR_PROBLEMS.fp" \
        && ok "fingerprint keys match the running kernel and no row lacks the current kid (tenants: $(grep -o 'tenants=[0-9]*' "$WORKDIR_PROBLEMS.fp" | head -1))" \
        || fail "MK_FINGERPRINT_KEYS in this shell differs from the running kernel ($kids_json)"
    else fail "fingerprint status: $(grep -E 'lacking|orphaned|unverified|NOT SAFE|Error' "$WORKDIR_PROBLEMS.fp" | tr '\n' ' ')"; fi
    rm -f "$WORKDIR_PROBLEMS.fp"
  else fail "mk-keyctl not found at $KC (set MK_KEYCTL)"; fi
  # Restore gate in report mode must agree the environment is recoverable (never
  # enables anything). Every check except global_dispatch_disabled must pass.
  RG="${MK_RESTORE_GATE:-$ROOT/rust/target/release/mk-restore-gate}"
  if [ -x "$RG" ]; then
    MK_DATABASE_URL="$RO_URL" "$RG" --restored-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$WORKDIR_PROBLEMS.rg" 2>&1
    bad=$(grep -o '"check":"[a-z_]*","ok":false' "$WORKDIR_PROBLEMS.rg" | grep -v global_dispatch_disabled | tr '\n' ' ')
    nchecks=$(grep -c '"check":' "$WORKDIR_PROBLEMS.rg")
    if [ -z "$bad" ] && [ "$nchecks" -ge 6 ]; then ok "restore gate: every recoverability check passes ($nchecks checks)"
    else fail "restore gate FAIL: ${bad:-only $nchecks checks reported}"; fi
  else fail "mk-restore-gate not found at $RG (set MK_RESTORE_GATE)"; fi
  rm -f "$WORKDIR_PROBLEMS.rg"
  REC="${MK_ACCEPTANCE_RECORD:-$ROOT/deploy/kernel/ACCEPTANCE.md}"
  if [ -f "$REC" ]; then
    # Values must be real, not the template's placeholders; the result line
    # must be exactly `Result: ACCEPTED`.
    acceptance_ok() {
      local f v problems=""
      for f in "Date" "Device" "Android" "Kernel commit" "Agent commit" "Destination" "Task id" \
               "Evidence chain head" "Audit root" "Negative runs" "Reviewer" "Result"; do
        v=$(grep -m1 "^$f:" "$REC" | sed "s/^$f:[[:space:]]*//")
        [ -z "$v" ] && { problems="$problems [$f missing]"; continue; }
        grep -qE '<[^>]*>|YYYY|sha256:<|\|' <<<"$v" && problems="$problems [$f placeholder]"
      done
      v=$(grep -m1 '^Result:' "$REC" | sed 's/^Result:[[:space:]]*//; s/[[:space:]]*$//')
      [ "$v" = "ACCEPTED" ] || problems="$problems [Result must be exactly ACCEPTED, got '$v']"
      grep -m1 '^Task id:' "$REC" | grep -qE ': *[0-9a-f]{32} *$' || problems="$problems [Task id not 32-hex]"
      grep -m1 '^Evidence chain head:' "$REC" | grep -qE ': *[0-9a-f]{64} *$' || problems="$problems [Evidence chain head not 64-hex]"
      grep -m1 '^Audit root:' "$REC" | grep -qE ': *sha256:[0-9a-f]{64} *$' || problems="$problems [Audit root not sha256:<64-hex>]"
      grep -m1 '^Kernel commit:' "$REC" | grep -qE ': *[0-9a-f]{7,40} *$' || problems="$problems [Kernel commit not a sha]"
      grep -m1 '^Negative runs:' "$REC" | grep -qiE 'revoke[^=]*= *yes.*kill switch[^=]*= *yes' || problems="$problems [Negative runs must both be yes]"
      grep -m1 '^Destination:' "$REC" | grep -qi 'controlled test phone' || problems="$problems [Destination must state a controlled test phone]"
      [ -z "$problems" ] || { echo "   $problems" >&2; return 1; }
    }
    if acceptance_ok 2>"$WORKDIR_PROBLEMS"; then ok "real-device acceptance record complete and non-placeholder ($REC)"
    else fail "acceptance record rejected:$(cat "$WORKDIR_PROBLEMS")"; fi
  else fail "no real-device acceptance record at $REC — do not enable dispatch (docs/real-device-acceptance.md)"; fi
else
  echo "     (run with --for-enable before setting RUST_ACTION_KERNEL_ENABLED=1)"
fi

echo
echo "pre-flight: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
