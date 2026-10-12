# Strict checking for Node identity foundations

Accepted scope: incrementally close audit A5's semantic-analysis gap. The existing relay gate covers three policy modules, while Node key encoding, strict JSON and legacy signature implementation have no dedicated strict check. Check `packages/identity/key-id.mjs` and `signed-envelope.mjs` directly with the existing TypeScript dependency, `strict`, `noUncheckedIndexedAccess`, `checkJs` and no emit. Add a local npm command and the same command to the existing Node CI job.

Preserve runtime behavior: JSDoc annotations only, with parenthesized expressions where type assertions need them. Keep validation order, canonical serialization, parser errors, public runtime exports and all signing inputs unchanged. Use unknown for untrusted input and a recursive JSON value type for parser output. Do not use explicit any, diagnostic suppression, declaration stubs that hide implementations, new dependencies or weaker compiler options. Document casts for existing index bounds and validated Node API calls.

Sequence: save exact original sources; retain baseline diagnostics; annotate the implementations; confirm unchanged executable AST and runtime exports; verify the strict gate includes both source files and catches deliberate invalid assignments in temporary copies; run existing key/signing vectors, full root tests, SDK and organization checks, fixtures and interoperability. Check existing semantic gates for consumer compatibility. Obtain scoped review and update audit/readiness evidence. No cloud deployment, protocol, schema or hosting decision is part of this increment.

Completion covers these two modules only. Key-document/status/entity-envelope and trust preparation implementation checking remain separate work. Type checking does not replace runtime rejection tests or cryptographic/security acceptance. Back out only these annotations and the added command/configuration if required; preserve all earlier uncommitted work.

## Evidence

The baseline command uses the planned compiler flags against both source files and exits 2 with 45 diagnostics. Log: `/tmp/xeip-identity-types-baseline.log`. Those diagnostics are resolved without suppression or executable changes. The recursive JSON contract lives in `json-types.d.ts`; the direct implementation files are still checked. A compile-only consumer in `type-contracts.mts` retains KeyObject, seed/DER bytes, PEM, Node private-key options and JWK options as supported signing inputs, and exercises unknown validation inputs.

Original sources are retained in `/tmp/xeip-identity-types-before/`. Their SHA-256 values are `2e0f4c6b92bf44f97cd97ccec1fc5b4ed1043ba2b35259d3be703c236fe5a1ab` (key IDs) and `240b13aaf9edcb859ce2726f446a8cb9360eb25fcb689ec468cc68aa3539ea84` (signed envelopes). Final fingerprints: `/tmp/xeip-identity-types-sources.sha256`.

`/tmp/xeip-identity-types-verify.mjs` compares complete executable TypeScript ASTs before/after, excluding comments and parenthesized expression wrappers. Both match exactly. It then copies the actual configuration and files into an isolated temporary directory, verifies the clean check passes, and inserts an incompatible assignment separately into each implementation. Both are rejected with TS2322; temporary files are removed. Final log: `/tmp/xeip-identity-types-preservation-final.log`.

The first annotation pass exposed JSDoc recursive-alias and overload limitations plus narrowing requirements. An explicit recursive JSON interface and guard-based assertions resolve these without disabling strictness or hiding implementation bodies. Scoped review found two overly narrow contracts: arbitrary exception message values were typed as strings, and JWK private-key options were omitted. Both are corrected. The compile-only key consumer first reproduces the JWK omission (TS2322, `/tmp/xeip-identity-types-jwk-red.log`), then passes with the corrected union (`/tmp/xeip-identity-types-jwk-green.log`). A synthetic Node probe confirms identical JWK signatures and unchanged number/undefined/object exception diagnostics against the saved baseline: `/tmp/xeip-identity-types-contract-probe.log`. Review of the corrections reports no remaining Critical, Important or Minor findings.

Verification completed with exit 0:

| Check | Result | Local evidence |
| --- | --- | --- |
| Dedicated identity gate and compile-only callers | Passed | `/tmp/xeip-identity-types-jwk-green.log` |
| Existing relay, organization, console, Cloudflare and SDK type gates | Passed | `/tmp/xeip-identity-types-*-final.log` and `/tmp/xeip-identity-types-sdk-check-final.log` |
| Root runtime suite | 385 passed | `/tmp/xeip-identity-types-root.log` |
| Organization runtime suite | 211 passed | `/tmp/xeip-identity-types-organization.log` |
| TypeScript SDK suite | 241 passed | `/tmp/xeip-identity-types-sdk.log` |
| Shared fixture vectors | Passed | `/tmp/xeip-identity-types-fixtures.log` |
| Node/TypeScript/Rust interoperability | 36 passed | `/tmp/xeip-identity-types-interop.log` |

The runtime suites completed before the final review corrections to annotations/formatting. The final AST comparison confirms the executable code remains identical to the baseline; affected consumer type gates were rerun after the corrections. No runtime image or Cloudflare artifact rebuild is claimed. The dedicated CI step is configured but has not run on hosted CI. No dependency, deployment, commit or release changed. This bounded semantic-analysis increment is complete; A5's remaining implementation coverage and all independent production acceptance gates remain open.
