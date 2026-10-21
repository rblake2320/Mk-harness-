#!/usr/bin/env bash
# Observability gate (contract O6/O7):
#  1. alert rules parse;
#  2. every metric name referenced by a rule is actually registered by a kernel
#     binary (no phantom metrics in alerting), `up` excepted;
#  3. promtool unit tests: each paging rule fires on injected series and stays
#     silent on the healthy counterpart;
#  4. the dashboard JSON parses and references only registered metrics.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OBS="$ROOT/deploy/observability"
command -v promtool >/dev/null || { echo "promtool not installed"; exit 2; }

promtool check rules "$OBS/alerts.yml"

# Registered names: every `registry.register("mk_…"` / `reg!(r, "mk_…"` in the Rust sources.
# (`register(` may be followed by a newline before the name — match across lines.)
grep -rlE 'registry.register|reg!\(' "$ROOT/rust/crates" --include=*.rs \
  | xargs perl -0ne 'while (/(?:\.register\(|reg!\(\s*r,)\s*"(mk_[a-z0-9_]+)"/g) { print "$1\n" }' \
  | sort -u > /tmp/mk-registered.txt
count=$(wc -l < /tmp/mk-registered.txt)
[ "$count" -ge 25 ] || { echo "only $count registered metrics found; extraction broken"; exit 1; }

missing=0
check_refs() {
  # $1 = file; metric refs are mk_* tokens; suffixes _total/_bucket/_count/_sum map to the base name.
  grep -oE 'mk_[a-z0-9_]+' "$1" | sort -u | while read -r m; do
    base="${m%_total}"; base="${base%_bucket}"; base="${base%_count}"; base="${base%_sum}"
    grep -qx "$m" /tmp/mk-registered.txt || grep -qx "$base" /tmp/mk-registered.txt \
      || { echo "UNREGISTERED metric referenced in $(basename "$1"): $m"; exit 1; }
  done
}
check_refs "$OBS/alerts.yml"
check_refs "$OBS/dashboards/kernel.json"

promtool test rules "$OBS/alerts_test.yml"
python3 -I -c "import json,sys; d=json.load(open(sys.argv[1])); assert d['uid']=='mk-kernel' and len(d['panels'])>=20, 'dashboard shape'" "$OBS/dashboards/kernel.json"

paging=$(grep -c "severity: page" "$OBS/alerts.yml")
tested=$(grep -oE 'alertname: MK[A-Za-z]+' "$OBS/alerts_test.yml" | sort -u | wc -l)
echo "alert rules ok: $(grep -c 'alert: ' "$OBS/alerts.yml") rules, $paging paging, $tested distinct rules unit-tested, $count registered metric names"
