# mecha_policy — Intent

The ONE shared Mecha entitlement policy implementation, so validate,
RotShield and every future Mecha app make identical license decisions from
identical inputs, and a policy bug is fixed in one place.

**Users:** the Mecha app cores (validate, rotshield — native Zig import) and
their FFI consumers (validate_gui, entropy_shield GUIs — through their app
core's own FFI, never linking this directly). mecha-commerce consumes the
semantics via the shared vector manifest, not this code.

**Scope:** pure decision logic over a sigil-VERIFIED payload: schema
validity, key-role-to-grant-class binding, product match, version ceiling,
clock rollback (against an injected high-water mark), UTC day-inclusive
expiry, operation coverage. NO I/O, NO clock reads, NO crypto — sigil
verifies bytes upstream; apps own persistence, admission points and
presentation. Commercial policy (pricing, refunds, issuance) stays in
MECHA_RELEASE_PLAN / mecha-commerce.

**Authority:** sigil docs/MECHA_LICENSE_CONTRACT_V1.md (rev 1.1) and the
vector manifest sigil examples/license_vectors/manifest.json
(mecha-license-vectors/1) — the unit tests embed that manifest's every
eval verbatim; changing semantics requires a coordinated vector-schema
bump per the contract.

**Success:** each app's gate passes the shared vector matrix against its
own build using this module; About/CLI status and actual admission agree
because they consult the same decision.
