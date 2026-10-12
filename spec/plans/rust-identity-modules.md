# Rust identity module boundaries

Scope: resolve the Rust decomposition part of audit A5 under the authorized production-hardening work. The identity crate currently places key encoding, canonical JSON, envelope signatures, key-document trust, status and device rotation in a2,949-line root module. This is an internal organization change, with no release or deployment.

Preserve the crate-root public API, constants, error reasons, signing domains, serialization, strict parsing, validation order, trust/rotation semantics, dependency lock and Rust1.81 minimum. Preserve the independent Rust implementation and existing shared vectors. Profile-specific timestamp validation remains distinct; moving shared helpers must not broaden accepted dates. Independent cryptographic review remains an external gate.

## Boundaries

Keep `lib.rs` as crate documentation, private module declarations and explicit public re-exports. Use focused modules for key IDs, internal binary encoding, curve/key guards, canonical JSON and strict parsing, legacy envelope signatures, key documents and anchored trust, status documents, device rotation and shared UTC helpers. Keep the existing entity-envelope implementation separate and replace its parent wildcard import with explicit dependencies. Move existing unit tests into a private test module with explicit helper imports. No new public module paths or internal helper exports are needed.

## Execution and verification

1. Save the exact starting Rust sources and public-item inventory. Run the current workspace/all-target tests on Rust1.94.1 before moving code. Record existing failures instead of treating them as refactor regressions.
2. Move complete declarations and implementations mechanically. Restrict helper visibility to the crate where sibling modules need it. Preserve function bodies, type definitions and constant values; compare extracted sections against the saved source. Update module-local imports and intra-doc links only as required.
3. Verify the crate-root export set and all existing unit/integration/example callers. Run formatting, workspace/all-target tests on Rust1.94.1 and1.81, Clippy with warnings denied on1.94.1, and rustdoc with broken links denied. Run the existing Node/TypeScript/Rust interoperability suite sequentially afterward. Do not add tests that merely assert file placement.
4. Obtain a scoped review of API/semantic preservation and module boundaries. Correct findings and rerun checks whose scope is affected. Update the audit/readiness record, distinguishing this completed maintainability work from security and production acceptance.

Each step depends on the preceding one. Keep heavy verification sequential with the existing Cloudflare work. No schema, dependency, infrastructure, policy or credential change is involved. Back out only this extraction using the saved Rust files and remove only newly created modules; preserve all earlier uncommitted work. Completion requires unchanged public contracts and passing verification, not fewer lines in `lib.rs` alone.

## Evidence

The baseline on Rust 1.94.1 passed **80 tests**, with one existing ignored live-relay smoke that requires an already running relay. The extraction does not change that test or claim it was exercised. Baseline log: `/tmp/xeip-rust-modules-baseline.log`.

Exact original sources and the 53-item public inventory are saved under `/tmp/xeip-rust-modules-before/`; original `lib.rs` SHA-256 is `4378cb0982a9746efbfa4cea2bab07640e053c01a5613a942620cb666fbbe442`. The implementation now uses an 82-line root, ten private implementation modules and a private unit-test module. `key_document.rs` remains a cohesive 727-line document/chain/trust implementation. Dependencies and the Rust 1.81 minimum are unchanged.

The preservation comparison accounts for every original nonblank implementation line, including all types, constant values, function/impl bodies and existing tests. After formatting, it compares non-comment source lines while allowing imports, indentation and crate-only helper visibility to change; string contents remain part of the comparison. All 53 original public names are explicitly re-exported with no duplicates or additions. Evidence: `/tmp/xeip-verify-rust-extraction.py` and `/tmp/xeip-rust-modules-preservation.json`. This supports mechanical preservation; it is not an independent cryptographic audit.

Final sequential verification completed with exit 0:

| Check | Result | Local log |
| --- | --- | --- |
| Rust 1.94.1 workspace, all targets, locked | 80 passed, 1 existing live-relay smoke ignored | `/tmp/xeip-rust-modules-1.94.log` |
| Rust 1.81.0 workspace, all targets, locked | 80 passed, same 1 ignored | `/tmp/xeip-rust-modules-1.81.log` |
| Rust 1.94.1 formatting | Passed | `/tmp/xeip-rust-modules-format.log` |
| Rust 1.94.1 Clippy, all targets, warnings denied | Passed | `/tmp/xeip-rust-modules-clippy.log` |
| Rustdoc, broken intra-doc links denied | Passed | `/tmp/xeip-rust-modules-rustdoc.log` |
| Node/TypeScript/Rust interoperability, Rust 1.94.1 | 36 passed, including actual loopback relay exchanges | `/tmp/xeip-rust-modules-interop.log` |

The first extraction compiler check found misplaced module documentation, mechanically over-selected imports and missing crate-only helper visibility. These were corrected before the passing checks; no algorithm or assertion changed. The initial source comparison also needed to normalize rustfmt line wrapping after visibility changes. Both failures are preserved in the execution transcript; the final comparison includes original string contents. Final source fingerprints: `/tmp/xeip-rust-modules-sources.sha256`.

Scoped read-only review independently confirmed the 53 exports, complete source preservation, 14 unchanged unit tests, explicit dependency resolution and distinct timestamp rules. It reported no Critical, Important or Minor findings. The maintainability increment is complete locally. Production remains no-go: this increment does not prove hosted capacity, complete disaster recovery, independent cryptographic/security review or real-organization acceptance. No deployment, dependency change, commit or release occurred.
