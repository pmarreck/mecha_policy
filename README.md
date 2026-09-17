# mecha_policy

[![Mechatron Prime CI](https://img.shields.io/endpoint?url=https%3A%2F%2Fthelio-nixos.tail66c90.ts.net%2Fbadges%2Fmecha_policy.json&style=for-the-badge)](https://thelio-nixos.tail66c90.ts.net/mechatron-prime/)

The ONE shared Mecha entitlement policy implementation. A sigil-verified
license payload goes in with an injected clock, product, app version and
trust role; a typed decision with a stable reason code comes out. Every
Mecha app gate, `license status` surface and About panel consults this
same decision — pure Zig core (no I/O, no clock reads), C FFI, and a
`mecha-policy` CLI that dogfoods the FFI.

Authority: sigil `docs/MECHA_LICENSE_CONTRACT_V1.md` (rev 1.1) and the
vector manifest `sigil/examples/license_vectors/manifest.json`, whose every
expected decision is embedded verbatim in this repo's unit tests.

Build `./build` · Test `./test`
