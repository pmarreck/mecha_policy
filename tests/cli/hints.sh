#!/usr/bin/env bash
# Device-hint CLI tests (contract section 15.1), driven row by row from
# sigil's examples/hint_vectors/manifest.json (the spec, hashed there by
# coreutils): every known answer prints its exact hint; every reject exits 65
# with no hint on stdout. Raw inputs are hex in the manifest so whitespace and
# 0x00 bytes reach the CLI exactly. A missing sibling checkout FAILS. `set -u` only.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN="${MECHA_POLICY_BIN:-$REPO_ROOT/zig-out/bin/mecha-policy}"
SIGIL_DIR="${SIGIL_DIR:-$REPO_ROOT/../sigil}"
M="$SIGIL_DIR/examples/hint_vectors/manifest.json"
PASS=0; FAIL=0
pass() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s (%s)\n' "$1" "${2:-}" >&2; return 0; }
WORK="${TMPDIR:-/tmp}/mecha-policy-hints-$$"; mkdir -p "$WORK" || exit 1
trap 'rm -rf "$WORK"' EXIT
for need in "$BIN" "$M"; do
	if [[ ! -e "$need" ]]; then echo "FATAL: $need missing" >&2; exit 1; fi
done
if ! command -v jq >/dev/null 2>&1; then echo "FATAL: jq missing" >&2; exit 1; fi
unhex() { printf '%s' "$1" | sed 's/../\\x&/g' | xargs -0 printf '%b'; }

nk=$(jq '.kats | length' "$M")
for ((i = 0; i < nk; i++)); do
	read -r prod kind raw want < <(jq -r ".kats[$i] | \"\(.product) \(.kind) \(.raw_hex) \(.hint)\"" "$M")
	unhex "$raw" > "$WORK/v"
	got=$("$BIN" hint-hash --product "$prod" --kind "$kind" --value-file "$WORK/v" 2> "$WORK/err"); rc=$?
	[[ $rc -eq 0 && "$got" == "$want" ]] && pass "hint KAT $i ($kind, $prod)" || fail "hint KAT $i ($kind, $prod)" "rc=$rc got=$got"
done
nr=$(jq '.rejects | length' "$M")
for ((i = 0; i < nr; i++)); do
	read -r prod kind raw < <(jq -r ".rejects[$i] | \"\(.product) \(.kind) \(.raw_hex)\"" "$M")
	unhex "$raw" > "$WORK/v"
	got=$("$BIN" hint-hash --product "$prod" --kind "$kind" --value-file "$WORK/v" 2> "$WORK/err"); rc=$?
	why=$(jq -r ".rejects[$i].why" "$M")
	[[ $rc -eq 65 && -z "$got" ]] && grep -q 'omit' "$WORK/err" && pass "hint reject $i ($kind: $why)" || fail "hint reject $i ($kind: $why)" "rc=$rc out=$got"
done
# The value is read from stdin too, and an unknown kind is a usage error.
printf 'S4EWNX0R123456K' | "$BIN" hint-hash --product mecha-validate --kind disk --value-file - > "$WORK/o" 2>/dev/null
[[ "$(cat "$WORK/o")" == "$(jq -r '.kats[0].hint' "$M")" ]] && pass "--value-file - reads stdin" || fail "--value-file - reads stdin"
"$BIN" hint-hash --product mecha-validate --kind serial --value-file "$WORK/v" > /dev/null 2> "$WORK/err"; rc=$?
[[ $rc -eq 64 ]] && grep -q 'disk, mac or tpm' "$WORK/err" && pass "unknown kind exits 64 and names the kinds" || fail "unknown kind exits 64" "rc=$rc"
echo "hints: $PASS passed, $FAIL failed"
exit "$FAIL"
