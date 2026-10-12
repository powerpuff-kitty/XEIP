# Human approval console

Status: implementation contract for the existing self-hosted organization runtime. This closes the missing browser interaction path, not the capacity/recovery/security acceptance gates. Hosting exploration does not replace the selected Keycloak identity provider.

## User workflow

An approver opens `/console/`, signs into the pinned Keycloak realm using authorization code with PKCE S256, and uses a browser device key. On first use, explicitly generate a non-extractable Ed25519 signing key and store it in IndexedDB, scoped to the configured issuer and provider subject. Export only the public key ID and account details for operator enrollment. The operator must endorse the key in the human entity's signed key document, publish a fresh status and configure its exact provider binding/membership. Login does not enroll a key or grant approval authority.

The first workflow accepts a session ID and action ID from the requesting agent. An optional bounded fragment deep link may prefill these public identifiers; never take action arguments, digests, issuer, recipient, entity mapping or automatic decisions from a URL. A navigational selection may survive login in session storage; tokens and action content must not. An organization-wide pending inbox and automated enrollment/status distribution remain subsequent rollout work rather than being implied by this first workflow.

The console inspects the action through the existing signed API, validates its response shape and independently recomputes its content digest. Display requester subject/entity/key, target ID/revision/recipient, tool, all arguments, session/request IDs, policy revision, digest, expiry and current state. Use plain text for every untrusted value. Approval and rejection require explicit buttons on that exact immutable review. Block self-approval, stale/non-pending actions, expired reviews and concurrent decisions locally; the server remains authoritative.

Before a decision, refresh the token if needed and build a fresh signed envelope. Send the previously reviewed digest without replacing it from a background refresh. Any uncertain response clears the actionable review and requires inspection; no automatic decision retry. Inspection after expiry or completion remains available. Show approval as consent, not proof of tool execution. Explain that signing out does not withdraw prior consent and provide explicit revoke for eligible pending/approved actions under the existing server policy.

## Browser and identity boundaries

Use exact pinned `keycloak-js` from the application bundle; no CDN scripts. Public client only, standard code flow, PKCE S256, exact callback `/console/`, `responseMode: fragment`, nonce/state protection and disabled login iframe. Access/refresh tokens remain in the adapter's memory. Clear the view on logout, account change, token refresh failure or key mismatch. Initial supported browser must implement Ed25519 WebCrypto and IndexedDB CryptoKey cloning; otherwise show an actionable unsupported-browser state without an extractable-key fallback.

Separate browser key storage, signed action client and DOM rendering. Snapshot reviewed data before asynchronous work and keep decision authority attached only to reviews returned by that client instance. Use the existing SDK signature format; do not invent a new signature or weaker web-only API. A lost browser key requires operator re-enrollment/revocation; do not silently rotate an enrolled device.

The optional protected server configuration is `console: {clientId}`. Require that ID in the authentication allowlist. Public `/console/config` returns only issuer, public client ID, gateway and API audience. `GET /v1/console/profile` authenticates and introspects a mapped principal, requires the configured console client and approver role, and returns only subject/entity/kid/expiry. It does not mutate enrollment or bypass signatures for actions. Release its request-local token in every exit path. Existing TLS, exact Host/Origin checks, connection limits, deadlines and redacted telemetry apply.

Serve only a fixed set of built assets; no request-derived file path resolution. Console is disabled unless configured. Pin self-only scripts/styles, issuer-only external connections, no framing, no objects, no base URL override and no referrer. Return non-cacheable authenticated/profile/action responses. Do not expose secrets in bootstrap configuration, source maps, logs or errors. Package bundled third-party code with license/inventory evidence.

## Visual design

This is a decision workspace. Use a pale blue-grey canvas `#f3f6fa`, white document surface `#ffffff`, ink `#17324d`, blue action `#175f9e`, red denial `#a52a35` and a quiet border `#c4d1df`. Use locally available humanist sans-serif text (Segoe UI/Candara with system fallbacks), generous readable action details, and monospace only for the argument JSON and actual cryptographic identifiers. No remote fonts or decorative animation.

Desktop: a compact account/device column beside a broad action review; mobile: one column with the decision controls following all action content. Labels and values are left aligned. Approval/rejection have distinct text and focus states; state is never conveyed by color alone. Keep keyboard order natural, announce status/errors, label every input, preserve visible focus and support reduced motion. The visual emphasis is the exact request and its decision controls rather than dashboard statistics.

## Verification and remaining gates

Unit tests: canonical digest and exact response validation; mutated reviews and changed tokens; fresh signature after token waits; bounded malformed/oversized/duplicate response handling; no retries after ambiguous decisions; device key persistence and issuer/subject separation in a real browser.

HTTP/config tests: disabled-by-default routes, no secrets in bootstrap/profile, exact client and approver role, malformed/duplicate headers, TLS/Host/Origin enforcement, profile deadline/abort behavior, static traversal and CSP, no regression to action request lifecycle.

Browser tests: actual DOM and crypto, persisted non-extractable keys, keyboard paths, no content injection, explicit inspect/approve/reject/revoke, changed/expired/terminal state, double-click protection, lost responses and token expiry/account switching. Exercise the pinned OIDC adapter against a controlled code/PKCE test issuer, then require real Keycloak/browser acceptance on reserved staging. Simulated browser/OIDC tests do not certify real provider deployment.

Rebuild the actual container and verify included assets, dependencies and immutable runtime. One fresh-context final review covers the whole console change. Independent security review, real human/operator usability, automated 500-user enrollment/status operation, real MCP target, unchanged SLO/restore tests and release sign-off remain open.

Source: [Keycloak JavaScript adapter](https://www.keycloak.org/securing-apps/javascript-adapter), checked 11 October 2026: public client with exact redirects/origins, authorization code, token refresh and in-memory tokens. The explicit XEIP controls above are this project's design decisions.
