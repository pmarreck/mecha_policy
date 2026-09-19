# mecha_policy — Plan

## In Progress
- [ ] Mechatron Prime CI (targets manifest + webhook + badge)
- [x] ABI LOCKED at 2d2a0be (abi_version 1): validate's first consuming
      commit ba3d1f6be pins this as a build.zig.zon git dependency, asserts
      abi_version in its status KV, embeds the vector manifest as unit
      tests, re-exports the decision through its FFI (validate_gui consumes
      that). Any exported-function or decision-code change now requires a
      versioned bump. — 2026-09-19 13:15 EDT

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
