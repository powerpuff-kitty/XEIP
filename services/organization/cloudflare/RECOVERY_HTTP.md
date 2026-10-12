# Experimental authenticated recovery transport

The provider-neutral client and handler now implement a bounded HTTPS protocol around an already-open recovery journal. The [Worker profile](WORKER.md#configure-action-recovery-before-initialization) can now construct the client; the journal handler still needs an explicitly initialized, separately hosted runtime. Nothing has been provisioned. This provides authenticated transport; it does not establish an independent failure domain or production recovery.

```js
const client = createRecoveryClient({
  url: "https://journal.example/v1/recovery",
  token: recoverySecret,
  options: journalOptions,
});
const service = await OrganizationService.open(storage, configuration, {
  options: journalOptions,
  client,
});
// In a separately operated journal runtime, after explicit initialize/open:
const handle = createRecoveryHandler({
  url: "https://journal.example/v1/recovery",
  token: recoverySecret,
  options: journalOptions,
  journal,
});
```

Imports are `./recovery-client.mjs`, `./recovery-http.mjs` and `./service.mjs`. `journalOptions` must pin the same organization, stream UUID and capacity limits at both ends and in persisted source enrollment. Existing populated sources still cannot enroll through this interface. Provisioning, separate storage and journal lifecycle belong to the host/operator; the handler exposes no initialization, reset, deletion, SQL or namespace selection.

Use a dedicated secret containing 32 cryptographically random bytes encoded as 64 lowercase hexadecimal characters. Supply it only from protected runtime configuration; never embed it in a URL, public profile, source control, logs or lifecycle intent. The credential grants read and append authority for one configured journal. It is not an owner, Keycloak or action-execution credential. Replacing the handler/client rotates the credential; drain old instances and reconcile in-flight writes before resuming. Automated rotation, secret distribution, network controls and operator audit remain deployment work.

The client pins an exact canonical HTTPS URL, sends credentials only there, refuses redirects and accepts only exact 200 JSON success. It never retries. The handler authenticates before reading data, rejects browser credentials/origins, and validates scope and every operation. Fixed errors omit payloads/credentials. Reads and writes use POST, no-store and a versioned JSON envelope.

Both boundaries admit one request at a time. The 24 MiB request cap carries the full 16 MiB journal payload in 64 base64 parts; responses cap at 384 KiB for one part plus its header. UTF8, duplicate keys, depth 16, actual and declared lengths and journal fields are checked. The journal timeout (100–10000ms) covers the transport operation, including reading the body. Stalled work retains admission until it settles; deadline/cancellation prevents a later journal call or successful response. Runtime continuation must retain outstanding work (the handler accepts the host's `waitUntil` capability). There is no availability guarantee if a trusted adapter ignores deadlines forever. Deployed Workers freeze clock readings during CPU work, so the boundary yields to due timers before outbound/journal calls and before accepting success; elapsed checks alone are insufficient. See [Cloudflare timing semantics](https://developers.cloudflare.com/workers/runtime-apis/performance/).

The client accepts decoded HTTP chunked responses with no Content-Length. Transfer-Encoding combined with Content-Length, unsupported coding chains, and transfer-encoded handler requests are rejected; actual decoded bytes still count toward the same limit. See [RFC 9112 chunked framing](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.1).

An append can commit even when its response is lost. Every client transport failure becomes `StoreUnavailable`; the source coordinator quarantines and requires fresh reconciliation. Do not repeat a tool effect. Entry receipts bind the requested sequence, identity, predecessor and payload descriptor; the coordinator additionally validates the complete chain and cumulative bytes. A downloaded part is bounded canonical base64 associated with a validated entry; **verify the complete reconstructed payload against the entry SHA256 before using it for recovery**, because a per-part response alone cannot validate a multipart payload digest. TLS and the credential do not protect against a privileged journal operator or coherent rollback of all witnesses.

Local tests cover actual workerd/SQLite transport, full 16 MiB and multipart records, restart, synchronization before receipt, wrong credentials and source reconciliation after a lost response, including exactly one tool effect and consumed-claim rejection after reopen. Hosted CPU/memory, TLS, IAM, capacity and independent durability are unverified. Complete source restore, trust/authority/admin recovery, retention and the 500-user/200-agent/120-action-per-minute acceptance run remain required.

See [protocol](../../../spec/cloudflare-recovery-transport.md), [execution evidence](../../../spec/plans/cloudflare-recovery-transport.md), [action recovery](ACTION_RECOVERY.md), and run `npm run test:cloudflare` plus `npm run typecheck:cloudflare`.

The [recovery bundle collector](RECOVERY_ARCHIVE.md) now reads a fixed complete journal prefix into private durable files and verifies payloads, chained history and prior witnesses offline. Separate action interpretation checks exact transition continuity and consumed claims. It performs no restore or replay and does not certify independent hosting or zero-loss recovery.
