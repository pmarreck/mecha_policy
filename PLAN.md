# mecha_policy — Plan

## In Progress
- [ ] Mechatron Prime CI (targets manifest + webhook + badge)
- [ ] Negotiate ABI pin confirmation from validate (native Zig import) and
      relay to validate_gui (they target validate's re-export)

## Future
- [ ] `not_before` support if a future product ever mints future-dated
      terms (contract: currently NO valid_from, by Peter's decision)
- [ ] Integration script cross-checking the embedded eval table against
      sigil's manifest.json when the sibling checkout exists (drift guard)

## Completed
- [x] Scaffold + core decide() TDD'd red->green against the full
      mecha-license-vectors/1 manifest (21 evals), 16-case malformed corpus,
      rollback, binding symmetry, high-water format; C FFI + mecha-policy
      CLI dogfooder; 13 CLI assertions; ./test ALL PASS.
      — 2026-09-17 12:55 EDT
