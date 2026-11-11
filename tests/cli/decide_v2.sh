#!/usr/bin/env bash
# ABI 2 decide CLI tests, driven row by row from sigil's
# examples/license_vectors_v2/manifest.json (mecha-license-vectors/2, the
# spec with hand-written expects): each envelope is verified by native sigil
# FIRST (verify before parse), then decided with --app-major AND --app-minor.
# A missing sibling checkout or tool FAILS. `set -u` only.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN="${MECHA_POLICY_BIN:-$REPO_ROOT/zig-out/bin/mecha-policy}"
SIGIL_DIR="${SIGIL_DIR:-$REPO_ROOT/../sigil}"
SIGIL="${SIGIL_BIN:-$SIGIL_DIR/zig-out/bin/sigil}"
V="$SIGIL_DIR/examples/license_vectors_v2"; M="$V/manifest.json"
PASS=0; FAIL=0
pass() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s (%s)\n' "$1" "${2:-}" >&2; return 0; }
WORK="${TMPDIR:-/tmp}/mecha-policy-v2-$$"; mkdir -p "$WORK" || exit 1
trap 'rm -rf "$WORK"' EXIT
for need in "$BIN" "$SIGIL" "$M"; do
	if [[ ! -e "$need" ]]; then echo "FATAL: $need missing" >&2; exit 1; fi
done
if ! command -v jq >/dev/null 2>&1; then echo "FATAL: jq missing" >&2; exit 1; fi

nv=$(jq '.vectors | length' "$M"); rows=0
for ((i = 0; i < nv; i++)); do
	f=$(jq -r ".vectors[$i].file" "$M"); r=$(jq -r ".vectors[$i].signed_by_role" "$M")
	pub=$(jq -r --arg r "$r" '.trust_roles[$r].pubkey' "$M")
	case "$r" in test-beta) role=beta-license ;; test-paid) role=paid-license ;; *) fail "$f role $r"; continue ;; esac
	if ! "$SIGIL" verify "$V/$f" --pubkey "$V/$pub" -q > "$WORK/p.json" 2>/dev/null; then fail "$f verifies under $r"; continue; fi
	ne=$(jq ".vectors[$i].policy_evals | length" "$M")
	for ((j = 0; j < ne; j++)); do
		read -r now hwm prod ma mi want < <(jq -r ".vectors[$i].policy_evals[$j] | \"\(.now_utc_date) \(.clock_high_water // \"-\") \(.product) \(.app_major) \(.app_minor) \(.expect)\"" "$M")
		# An eval with clock_high_water passes that stored mark; without it, none.
		mark=(); at="$now"
		[[ "$hwm" != - ]] && { mark=(--hwm "$hwm"); at="$now (mark $hwm)"; marks=$((${marks:-0} + 1)); }
		got=$("$BIN" decide --payload "$WORK/p.json" --role "$role" --product "$prod" --app-major "$ma" --app-minor "$mi" --now "$now" "${mark[@]}" 2>/dev/null)
		[[ "$got" == "$want" ]] && pass "$f $prod $ma.$mi @ $at -> $want" || fail "$f $prod $ma.$mi @ $at" "want $want got $got"
		rows=$((rows + 1))
	done
done
[[ $rows -ge 20 ]] && pass "$rows manifest evals exercised" || fail "manifest evals exercised" "$rows"
[[ ${marks:-0} -ge 4 ]] && pass "${marks:-0} of them pass a stored clock mark" || fail "manifest evals with a clock mark" "${marks:-0}"
"$BIN" decide --payload "$WORK/p.json" --role paid-license --product mecha-validate --app-major 1 --now 2026-10-17 > /dev/null 2> "$WORK/err"; rc=$?
[[ $rc -eq 64 ]] && grep -q -- '--app-minor' "$WORK/err" && pass "decide without --app-minor is a usage error naming it" || fail "decide requires --app-minor" "rc=$rc"
"$BIN" decide --payload "$WORK/p.json" --role paid-license --product mecha-validate --app-major 1 --app-minor -1 --now 2026-10-17 > /dev/null 2>&1; rc=$?
[[ $rc -eq 64 ]] && pass "a negative --app-minor is a usage error" || fail "negative --app-minor" "rc=$rc"
echo "decide v2: $PASS passed, $FAIL failed"
exit "$FAIL"
