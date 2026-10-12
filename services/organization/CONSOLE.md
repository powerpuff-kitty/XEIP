# Human approval console

The optional console serves a first human workflow at `/console/`: Keycloak login, browser device enrollment, inspection, explicit approval/rejection and revocation. It uses the same signed API as other clients. It does not create an approval inbox, enroll a key automatically, or execute a tool from the browser.

## Enable it

Build the browser assets with `npm ci --ignore-scripts --no-audit` and `npm run build:console`. The organization image builds and includes them automatically. Add this field to the protected organization configuration:

```json
"console": { "clientId": "approval-console" }
```

The client ID must also appear in `authentication.clientIds`. Omitting `console` disables its assets, bootstrap and profile endpoint. Run the normal configuration check and restart the service after configuration changes; signed trust-document updates use the existing reload procedure. Follow [operations](OPERATIONS.md) for TLS, protected files, migration and lifecycle requirements.

Configure a **public** Keycloak client named `approval-console`: standard authorization-code flow, PKCE S256, no client secret, implicit flow disabled, and direct-access grants disabled. Set the exact redirect and post-logout redirect to `https://YOUR-XEIP-HOST/console/` and Web Origins to that exact HTTPS origin, including a non-default port if used. Do not use wildcard redirects. Issued access tokens must include **both** the API audience (`authentication.audience`, for example `xeip-api`) **and** `authentication.introspectionClientId` as audiences; the backend requires both. Retain Keycloak’s default `basic` client scope (which supplies the human `sub` claim), include the `roles` scope, and configure the existing API `approver` role. A realm import that restricts default scopes to only `roles` is insufficient for human login. The console pins standard Keycloak endpoints beneath the configured realm issuer.

Both the identity provider and XEIP must be reachable over trusted HTTPS from the approver's browser. The initial browser requires Ed25519 WebCrypto and IndexedDB persistence of CryptoKey objects; current Chrome was tested locally. Other browser families have not yet been certified. No CDN or remote font is required. Browser tokens remain in memory; temporary OIDC state/PKCE metadata is managed by the pinned adapter.

## Enroll the first browser

1. The user signs in and explicitly chooses **Create device key**. The browser retains a non-extractable signing key in IndexedDB. The displayed enrollment request contains only the configured issuer, provider subject and public key ID.
2. An operator verifies the person's identity and public request through an independent trusted channel. A copied request is not proof of organizational membership. Endorse that key as a device of the intended human entity using the existing signed [key document](../../spec/identity-keys.md) and [live trust](../../spec/live-entity-trust.md) procedures, with fresh status and protected checkpoints. Never import an entity root private key into this console.
3. Configure the exact subject/entity/key binding in `authentication.bindings`, ensure the provider role and session approver membership are correct, and apply the protected configuration/trust changes. Current configuration maps each provider subject to one signing key; a second browser requires a deliberate binding/re-enrollment change, not automatic additional authority.
4. The user chooses **Check enrollment**. A matching profile enables signed inspection; server policy and live key/provider checks still govern each operation.

If storage was cleared or a key is corrupt, arrange operator revocation and re-enrollment. The console never replaces an existing corrupt key automatically. Non-extractability prevents private-key export through WebCrypto; it does not protect against malicious code already executing in the same origin. Preserve the CSP and trusted static-asset supply chain.

## Review and recover

Enter the session and action IDs supplied by the agent, then inspect. Signed API session IDs must be absolute URIs within the policy identifier limits, for example `urn:xeip:session:operations`; setup rejects bare names such as `operations`. Check the requester, target revision/recipient, tool, complete arguments, expiry, policy and digest before deciding. Approval binds those exact details; it does not confirm execution. A different request requires another review.

A failed or lost response does not prove the decision failed. Inspect again to see durable state; the console never automatically retries a decision. `indeterminate` execution requires operator reconciliation with the tool, not blind resubmission. Signing out does not withdraw existing consent. Explicitly revoke an eligible action before execution, or use the documented membership/key revocation controls.

## Evidence and remaining work

`npm run typecheck:console`, `npm run test:organization` and `npm run test:console:browser` cover the client/server boundaries. Run `npm run build:console` first for browser tests, and install Chromium with `npx playwright install chromium`. An existing Chrome binary can be selected through `XEIP_CHROME_PATH`. Tests use disposable browser contexts and a controlled code/PKCE issuer; they do not contact an organization's identity provider or tools.

A separate `npm run test:console:keycloak` command builds assets and runs a real public-client Keycloak authorization-code/PKCE flow over fixture HTTPS, operator device enrollment, the Node HTTPS/PostgreSQL service and the official MCP fixture server. It does not exercise a hosted Cloudflare console. It requires Docker with the pinned Keycloak/PostgreSQL images and Chromium (or `XEIP_CHROME_PATH`). It creates only owned disposable loopback fixtures and synthetic credentials. The child Node process trusts the fixture CA explicitly; browser certificate bypass is confined to its disposable context. No browser traces or bearer/password output are recorded. The local synthetic workflow passes; [audit evidence](../../spec/audits/2026-10-11-keycloak-browser.md) records the defects it exposed and verification limits. A real organization deployment is still a separate acceptance gate.

The packaged artifact includes fixed assets, SHA-256 checksums, the pinned Keycloak adapter and its license/inventory. Organizational Keycloak/browser acceptance, independent security and usability review, automated enrollment/status operations for 500 users, an organization-wide inbox, and the capacity/recovery targets remain release gates. Cloudflare exploration does not supply those missing acceptance results.

References: [Keycloak basic client scope and subject claim](https://www.keycloak.org/docs/26.7.2/upgrading/#new-default-client-scope-basic), [Keycloak JavaScript adapter](https://www.keycloak.org/securing-apps/javascript-adapter), checked 11 October 2026.
