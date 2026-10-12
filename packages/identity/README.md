# Node identity runtime

Shared Node implementations for relay and organization services. Import the specific module needed:

| Module                                                   | Responsibility                                                                 |
| -------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `key-id.mjs`                                             | Ed25519 multibase key IDs and entity/device URNs                               |
| `signed-envelope.mjs`                                    | Strict JSON, canonicalization, key codecs and detached 0.1 envelope signatures |
| `key-document.mjs`                                       | Root-signed key documents, chain validation and trust anchors                  |
| `identity-status.mjs`                                    | Signed revocations, monotonic status tracking and freshness                    |
| `entity-envelope.mjs`                                    | Endorsed-device, entity-bound 0.2 envelope signatures                          |
| `trust-preparation.mjs` / `trust-preparation-worker.mjs` | Bounded Node worker preparation; the owner retains persistence                 |
| `trust-state.mjs`                                        | Shared trust preparation and checkpoint rollback rules                         |

The first four retain their named exports through the original `tools/` paths. Those files are command-line wrappers; runtime consumers import this directory directly. Filesystem input, key generation commands and process dispatch stay in the wrappers. These modules require Node's crypto APIs and are not the browser SDK.

The TypeScript SDK and Rust implementation remain independent conformance consumers. Existing golden vectors and command-line tests constrain wire bytes and errors; `tools/identity-runtime.test.mjs` checks the transitive production import graph. The organization image ships only these runtime modules. See [the extraction plan](../../spec/plans/identity-runtime.md) for verification and rollback.

`npm run typecheck:identity` checks the actual `key-id.mjs` and `signed-envelope.mjs` implementations with strict TypeScript/JSDoc analysis and unchecked-index protection. Input guards remain necessary: types do not validate JSON, key bytes or signatures at runtime. `json-types.d.ts` describes parsed JSON; it does not replace either implementation with declaration stubs. This gate also runs in Node CI. The other modules above are not yet covered by this dedicated gate; expand the explicit boundary without weakening its compiler options. See [scope and verification](../../spec/plans/identity-static-analysis.md).
