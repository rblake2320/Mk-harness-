#!/usr/bin/env bash
# Linux/macOS twin of kernel-secrets.ps1. Generates every kernel secret into an
# .env file (mode 0600), keeping existing non-empty values unless --force.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${1:-.env}"; FORCE=0; [ "${2:-}" = "--force" ] && FORCE=1
DEVKEYS="$ROOT/rust/target/release/mk-devkeys"
[ -x "$DEVKEYS" ] || (cd "$ROOT/rust" && cargo build --release -q --bin mk-devkeys)

declare -A cur
if [ -f "$ENV_FILE" ]; then
  # Split on the FIRST '=' only; `IFS='=' read` would eat a trailing '=' of a
  # base64 value (MASTER_KEY) and silently corrupt it on re-run.
  while IFS= read -r line; do
    k=${line%%=*}; v=${line#*=}
    [[ "$k" =~ ^[A-Z0-9_]+$ ]] && cur["$k"]="$v"
  done <"$ENV_FILE"
fi
need() { [ "$FORCE" = 1 ] || [ -z "${cur[$1]:-}" ]; }
hex() { openssl rand -hex "$1"; }

need POSTGRES_PASSWORD && cur[POSTGRES_PASSWORD]=$(hex 24)
need JWT_SECRET        && cur[JWT_SECRET]=$(hex 48)
need MASTER_KEY        && cur[MASTER_KEY]=$(openssl rand -base64 32)
if need MK_ASSERTION_KEYS || need KERNEL_ASSERTION_PRIVATE_KEY; then
  gen=$("$DEVKEYS" gen)
  cur[MK_ASSERTION_KEYS]=$(sed -n 's/^MK_ASSERTION_KEYS=//p' <<<"$gen")
  cur[KERNEL_ASSERTION_PRIVATE_KEY]=$(sed -n 's/^DEV_PRIVATE_KEY=//p' <<<"$gen")
  cur[KERNEL_ASSERTION_KID]=k1
fi
for k in MK_DB_API_PASSWORD MK_DB_WORKER_PASSWORD MK_DB_RELAY_PASSWORD MK_DB_READONLY_PASSWORD; do
  need "$k" && cur[$k]=$(hex 24)
done
: "${cur[RUST_ACTION_KERNEL_ENABLED]:=0}"; : "${cur[KERNEL_PLATFORM_OPERATORS]:=}"
: "${cur[MK_MOBILE_INTAKE_URL]:=}"; : "${cur[MK_EGRESS_AUTHORITIES]:=}"

tmp=$(mktemp "$ENV_FILE.XXXX"); umask 077
for k in "${!cur[@]}"; do printf '%s=%s\n' "$k" "${cur[$k]}"; done | sort >"$tmp"
chmod 600 "$tmp"; mv -f "$tmp" "$ENV_FILE"
echo "wrote $ENV_FILE (${#cur[@]} keys). RUST_ACTION_KERNEL_ENABLED=${cur[RUST_ACTION_KERNEL_ENABLED]}"
