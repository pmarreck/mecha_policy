#!/usr/bin/env bash
# Installation-certificate CLI tests, driven row by row from sigil's
# examples/install_cert_vectors/manifest.json (the spec): each certificate is
# verified by native sigil FIRST (verify before parse), then decided. Machine
# hashes are checked against the manifest's coreutils-computed answers. A
# missing sibling checkout or tool FAILS. `set -u` only.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN="${MECHA_POLICY_BIN:-$REPO_ROOT/zig-out/bin/mecha-policy}"
SIGIL_DIR="${SIGIL_DIR:-$REPO_ROOT/../sigil}"
SIGIL="${SIGIL_BIN:-$SIGIL_DIR/zig-out/bin/sigil}"
V="$SIGIL_DIR/examples/install_cert_vectors"
PASS=0; FAIL=0
pass() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s (%s)\n' "$1" "${2:-}" >&2; return 0; }
WORK="${TMPDIR:-/tmp}/mecha-policy-install-$$"; mkdir -p "$WORK" || exit 1
trap 'rm -rf "$WORK"' EXIT

for need in "$BIN" "$SIGIL" "$V/manifest.json"; do
	if [[ ! -e "$need" ]]; then echo "FATAL: $need missing" >&2; exit 1; fi
done
if ! command -v jq >/dev/null 2>&1; then echo "FATAL: jq missing" >&2; exit 1; fi
M="$V/manifest.json"

# Machine-hash known answers (coreutils sha256sum in the generator).
n=$(jq '.machine_hash_kats | length' "$M")
for ((i = 0; i < n; i++)); do
	jq -j ".machine_hash_kats[$i].raw_id" "$M" > "$WORK/raw"
	prod=$(jq -r ".machine_hash_kats[$i].product" "$M")
	want=$(jq -r ".machine_hash_kats[$i].machine" "$M")
	got=$("$BIN" machine-hash --product "$prod" --raw-id-file "$WORK/raw")
	[[ "$got" == "$want" ]] && pass "machine-hash KAT $i ($prod)" || fail "machine-hash KAT $i ($prod)" "got $got"
done

# Every certificate row: sigil verify, then decide.
nv=$(jq '.vectors | length' "$M")
rows=0
for ((i = 0; i < nv; i++)); do
	file=$(jq -r ".vectors[$i].file" "$M")
	if "$SIGIL" verify "$V/$file" --pubkey "$V/test_install_cert.key.pub" -q > "$WORK/cert.json" 2>/dev/null; then :; else
		fail "$file verifies under test-install-cert"; continue
	fi
	ne=$(jq ".vectors[$i].evals | length" "$M")
	for ((j = 0; j < ne; j++)); do
		e=".vectors[$i].evals[$j]"
		lic=$(jq -r ".licenses[$(jq "$e.license" "$M")]" "$M")
		mach=$(jq -r ".machines[$(jq "$e.machine" "$M")]" "$M")
		args=(install --cert "$WORK/cert.json" --product "$(jq -r "$e.product" "$M")" --license-sha256 "$lic" --machine "$mach" --now "$(jq -r "$e.now" "$M")")
		hwm=$(jq -r "$e.hwm // empty" "$M"); [[ -n "$hwm" ]] && args+=(--hwm "$hwm")
		want=$(jq -r "$e.expect" "$M")
		got=$("$BIN" "${args[@]}" 2>/dev/null); rc=$?
		want_rc=1; [[ "$want" == "install_cert_valid" ]] && want_rc=0
		if [[ "$got" == "$want" && $rc -eq $want_rc ]]; then pass "$file eval $j -> $want"
		else fail "$file eval $j" "want $want/$want_rc got $got/$rc"; fi
		rows=$((rows + 1))
	done
done
[[ $rows -ge 11 ]] && pass "all $rows manifest rows exercised" || fail "manifest rows exercised" "only $rows"

# Caller bugs are usage errors, never verdicts.
"$BIN" install --cert "$WORK/cert.json" --product mecha-validate --license-sha256 abc --machine abc --now 2026-09-17 >/dev/null 2>&1
rc=$?; [[ $rc -eq 64 ]] && pass "malformed hash arguments exit 64" || fail "malformed hash arguments exit 64" "rc=$rc"

echo ""
echo "$PASS passed, $FAIL failed"
exit $(( FAIL > 0 ? 1 : 0 ))
