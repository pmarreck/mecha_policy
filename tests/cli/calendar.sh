#!/usr/bin/env bash
# Calendar validity as a classifier over a set, with an oracle mecha_policy did
# not write: GNU date. For each year (common, leap, century-common,
# century-leap, and the 0001/9999 bounds), every month 00..13 and the days at
# and around each month's end, `decide --now` must reject exactly the strings
# that GNU date does not round-trip. `set -u` only, per Mecha conventions.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN="${MECHA_POLICY_BIN:-$REPO_ROOT/zig-out/bin/mecha-policy}"
PASS=0; FAIL=0
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$1" >&2; return 0; }
if [[ ! -x "$BIN" ]]; then echo "FATAL: mecha-policy binary not found at $BIN" >&2; exit 1; fi
DATE=date; command -v gdate >/dev/null 2>&1 && DATE=gdate
if [[ "$("$DATE" -u -d 2024-02-29 +%F 2>/dev/null)" != 2024-02-29 || -n "$("$DATE" -u -d 2026-02-30 +%F 2>/dev/null)" ]]; then
	echo "FATAL: no GNU date to serve as the oracle" >&2; exit 1
fi
TD="${TMPDIR:-/tmp}/mp-cal-$$"; mkdir -p "$TD" || exit 1
trap 'rm -rf "$TD"' EXIT
printf '%s' '{"customer_email":"beta-tester@example.com","customer_name_canonical":"beta tester","expiry":"2026-10-17","features":"full","max_major":"1","offline_days":"365","payment_provider":"beta","payment_ref":"beta_0001","product":"mecha-validate","purchase_date":"2026-09-17","v":"1"}' > "$TD/beta.json"

valid=0; invalid=0
for y in 0001 1900 2000 2023 2024 2026 2100 2400 9999; do
	for m in 00 01 02 03 04 05 06 07 08 09 10 11 12 13; do
		for d in 00 01 27 28 29 30 31 32; do
			s="$y-$m-$d"
			if [[ "$("$DATE" -u -d "$s" +%F 2>/dev/null)" == "$s" ]]; then want=valid; valid=$((valid + 1)); else want=invalid; invalid=$((invalid + 1)); fi
			"$BIN" decide --payload "$TD/beta.json" --role beta-license --product mecha-validate --app-major 1 --app-minor 0 --now "$s" >/dev/null 2>&1
			rc=$?
			if [[ $rc -eq 64 ]]; then got=invalid; else got=valid; fi
			[[ "$got" == "$want" ]] && PASS=$((PASS + 1)) || fail "$s: GNU date says $want, decide --now says $got (exit $rc)"
		done
	done
done
# The sweep must contain both classes, or a constant classifier could pass.
[[ $valid -gt 0 && $invalid -gt 0 ]] && PASS=$((PASS + 1)) || fail "sweep covers both classes ($valid valid, $invalid invalid)"
echo "  calendar sweep: $valid valid and $invalid invalid dates against GNU date"
echo "$PASS passed, $FAIL failed"
exit $(( FAIL > 0 ? 1 : 0 ))
