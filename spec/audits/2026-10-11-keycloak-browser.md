# Real Keycloak browser approval audit

Status: local end-to-end workflow passes; production remains no-go. Checked11 October2026 on the current uncommitted hardening branch. This exercises the Node HTTPS/PostgreSQL service, a pinned development-mode Keycloak container, Chromium and the official local MCP fixture. Every identity and credential is synthetic. It is not a hosted Cloudflare console, organizational pilot, independent security review or capacity test.

## Defects found and corrected

**Browser requests failed the actual envelope contract.** The console generated a bare UUID for the signed envelope ID. The server correctly requires an absolute URI, so real inspection failed even though the earlier controlled tests verified the signature. The client now generates `urn:uuid:` IDs. Its transport tests apply the same SDK envelope validator as the server and use valid session URIs. The enhanced approval regression failed before the one-line fix and the full22-case client suite passes afterward (`/tmp/xeip-console-envelope-uri-{red,green}.log`). Server validation was not relaxed.

**Configuration accepted unusable sessions.** The protected runtime example used `operations`, and setup accepted bare session IDs even though the signed API requires the envelope session to be an absolute URI matching the action session. Node protected configuration and Cloudflare owner initialize/update now reject such policy sessions. The example uses `urn:xeip:session:operations`. Both new rejection tests failed before the guards; the complete configuration/profile files pass45/45 (`/tmp/xeip-session-uri-{red,green}.log`). Storage-only policy identifiers are unchanged.

**The public-client fixture omitted the human subject mapper.** Explicitly importing only the `roles` client scope produced a successful token exchange with valid issuer/client/audience/expiry/nonce checks but a failed subject check. Adding the default `basic` scope resolves real human login. The operator guide now preserves it. Keycloak documents that this scope supplies the subject and authentication-time claims. [Keycloak upgrade guide](https://www.keycloak.org/docs/26.7.2/upgrading/#new-default-client-scope-basic). No subject, nonce or token check was weakened.

The fresh scoped harness review found three additional issues: Playwright password-fill errors/debug output could expose synthetic credentials; nested signal handlers could exit before all fixture cleanup; and the exact-review assertions covered too few fields. The fixes sanitize credential-entry errors, disable inherited browser debug output, coordinate all registered cleanup callbacks and forward parent signals, and compare every displayed request/proof field and the exact executed arguments. Three subprocess/listener regressions pass and detect a temporary premature-exit mutation. The review covered the test harness; the later URI product fixes are supported by failing-then-passing regressions and actual integration, not a claim of an independent security review.

## Passing workflow

`npm run test:console:keycloak` builds the actual console bundle, uses a real public PKCE S256 client and automated synthetic human login, verifies that an unenrolled device cannot inspect, endorses the public browser key through the test operator, and checks persistence through a reload and a fresh real SSO redirect. The Node test process explicitly trusts the fixture CA; certificate bypass is confined to the disposable browser context.

It then compares the complete displayed request and digest, records approval without executing a tool, runs exactly one agent-requested MCP effect with the approved arguments, rejects replay, and proves the previously active browser token is denied after logout while still unexpired. It does not intercept OIDC, profile or action responses. The root signing key never enters the browser.

Terminal evidence: `/tmp/xeip-real-browser-envelope-fixed.log`, exit0. This run also passes the existing real Keycloak JWT/JWKS/introspection/revocation checks and PostgreSQL migration, crash/restart, backup/restore and restricted-runtime checks. Owned provider/database/browser fixtures were cleaned up.

## Regression and artifact evidence

- Organization tests205/205 and organization, console and Cloudflare strict types pass (`/tmp/xeip-real-browser-uri-unit.log`, `/tmp/xeip-real-browser-uri-{organization,console,cloudflare}-types.log`).
- The current controlled browser run passes16/17; its first case hit the30s total test budget during enrollment while other work overlapped. That unchanged case passes alone in4.4s (`/tmp/xeip-real-browser-uri-{controlled,focused}.log`). Preserve both results; do not label the full command green. The preceding version passed17/17 before the URI correction.
- The offline Cloudflare Worker builds and Wrangler dry-run passes (`/tmp/xeip-console-uri-dry-run.log`). Worker988174bytes/SHA256 `95554d1e0e5216d4ccf6425dbb318d4c4a7e787761f29c188595a7ed48026fd6`. The first dry-run command referenced the wrong `.jsonc` filename and failed without deployment; the corrected command uses generated `wrangler.json`. No cloud mutation occurred.
- Updated Linux image `xeip-organization:local-browser-uri-review` passes the nonroot, read-only, network-isolated integrity/dependency/runtime/maintenance smoke and redacted missing-configuration startup (`/tmp/xeip-console-uri-image.log`, exit0). Image `sha256:c0729a009dbaa8ffa7875814bc089bff5269a4b0d712afb9ec7e303314e9042d`,67,336,981bytes.
- The unchanged default HTTP/service-account Keycloak mode also passes its JWT/JWKS/introspection/revocation checks after the cleanup refactor (`/tmp/xeip-keycloak-default-compat.log`, exit0). Both offline Worker files independently match their manifest hashes/sizes and0600 modes. Hosted CI has not run.

Earlier failed runs remain in `/tmp/xeip-real-browser-{first,reviewed,diagnostic,basic-scope,controls}.log`: cold login navigation timeout, missing subject scope, unsupported fieldset-disabled matcher, then the real envelope-ID defect. They are not successful acceptance evidence.

## Remaining release gates

Use the [production-readiness record](../../PRODUCTION_READINESS.md) for the current ordered gates. Local synthetic workflow success does not establish500-user operations,120 actions/minute at P95≤2s, complete independent recovery within1h with no acknowledged-action loss, real private-tool connectivity, key/credential custody, retention, organizational enrollment/usability, hosted CI or external security/operator acceptance. Cloudflare hosting adoption remains a separate decision. The approved private Cloudflare smoke stays uninitialized on its earlier artifact; these changes do not authorize another deployment.
