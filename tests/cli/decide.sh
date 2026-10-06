#!/usr/bin/env bash
# CLI surface tests for mecha-policy, driven against the canonical sigil
# fixture payloads when present (skipped cases FAIL loudly if the sibling
# checkout is missing — CI vendors nothing, so this suite runs on dev boxes
# and the sibling-aware CI path). `set -u` only, per Mecha conventions.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN="${MECHA_POLICY_BIN:-$REPO_ROOT/zig-out/bin/mecha-policy}"

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s (%s)\n' "$1" "${2:-}" >&2; return 0; }

if [[ ! -x "$BIN" ]]; then
	echo "FATAL: mecha-policy binary not found at $BIN" >&2
	exit 1
fi

# expect <want_rc> <want_word> <desc> <args...>
expect() {
	local want_rc="$1" want_word="$2" desc="$3"
	shift 3
	local out rc
	out="$("$BIN" "$@" 2>/dev/null)"
	rc=$?
	if [[ $rc -ne $want_rc ]]; then
		fail "$desc" "expected exit $want_rc, got $rc"
		return
	fi
	if [[ -n "$want_word" && "$out" != "$want_word" ]]; then
		fail "$desc" "expected '$want_word', got '$out'"
		return
	fi
	pass "$desc"
}

# Inline payload fixtures (exact copies of the sigil vector payloads).
TD="$(mktemp -d "${TMPDIR:-/tmp}/mecha-policy-cli-XXXXXX")"
trap 'rm -rf "$TD"' EXIT
printf '%s' '{"customer_email":"beta-tester@example.com","customer_name_canonical":"beta tester","expiry":"2026-10-17","features":"full","max_major":"1","offline_days":"365","payment_provider":"beta","payment_ref":"beta_0001","product":"mecha-validate","purchase_date":"2026-09-17","v":"1"}' > "$TD/beta.json"
printf '%s' '{"customer_email":"forger@example.com","customer_name_canonical":"leaked key forgery","features":"full","max_major":"1","offline_days":"365","payment_provider":"paddle","payment_ref":"txn_forged_0001","product":"mecha-validate","purchase_date":"2026-09-17","v":"1"}' > "$TD/forged.json"
printf 'not json' > "$TD/garbage.json"

echo "mecha-policy CLI — binary: $BIN"

expect 0 authorized "valid beta grant on its expiry day is authorized" \
	decide --payload "$TD/beta.json" --role beta-license --product mecha-validate --app-major 1 --app-minor 0 --now 2026-10-17
expect 1 expired "the day after expiry is refused as expired" \
	decide --payload "$TD/beta.json" --role beta-license --product mecha-validate --app-major 1 --app-minor 0 --now 2026-10-18
expect 1 class_key_mismatch "the leaked-beta-key forgery is refused at class binding" \
	decide --payload "$TD/forged.json" --role beta-license --product mecha-validate --app-major 1 --app-minor 0 --now 2026-09-17
expect 1 wrong_product "a validate grant refuses rotshield" \
	decide --payload "$TD/beta.json" --role beta-license --product mecha-rotshield --app-major 1 --app-minor 0 --now 2026-09-17
expect 1 malformed "garbage bytes are malformed, not a crash" \
	decide --payload "$TD/garbage.json" --role beta-license --product mecha-validate --app-major 1 --app-minor 0 --now 2026-09-17
expect 1 clock_rollback "now behind the high-water mark is refused" \
	decide --payload "$TD/beta.json" --role beta-license --product mecha-validate --app-major 1 --app-minor 0 --now 2026-09-16 --hwm 2026-09-17
expect 64 "" "missing required arguments is a usage error" decide
expect 64 "" "an invalid --now date is a usage error, not a verdict" \
	decide --payload "$TD/beta.json" --role beta-license --product mecha-validate --app-major 1 --app-minor 0 --now nonsense
expect 66 "" "a missing payload file is a missing-input error" \
	decide --payload "$TD/nope.json" --role beta-license --product mecha-validate --app-major 1 --app-minor 0 --now 2026-09-17
expect 0 "" "--help exits zero" --help
expect 0 "" "--about exits zero" --about

# stdin form
out="$("$BIN" decide --payload - --role beta-license --product mecha-validate --app-major 1 --app-minor 0 --now 2026-09-17 < "$TD/beta.json" 2>/dev/null)"
if [[ $? -eq 0 && "$out" == "authorized" ]]; then
	pass "'-' reads the payload from stdin"
else
	fail "'-' reads the payload from stdin" "$out"
fi

# Path-with-spaces (CLI arg contract)
mkdir -p "$TD/with space" && cp "$TD/beta.json" "$TD/with space/b.json"
expect 0 authorized "payload paths with spaces work" \
	decide --payload "$TD/with space/b.json" --role beta-license --product mecha-validate --app-major 1 --app-minor 0 --now 2026-09-17

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
exit "$FAIL"
