# Experimental complete organization bundle

`organization-bundle.mjs` collects the coordinated source checkpoint and all of its action, authority and administrative history into protected local files. The repository now includes a private owner transport and Node collection CLI. They use the existing owner service binding; no public HTTP administration route exists. The previously approved private smoke deployment has not been updated and does not provide these new commands. Maximum-source resource measurements and hosted acceptance remain incomplete.

The operator configuration must select one `OwnerEntrypoint` service binding with an explicit operator identity and a `remote` flag matching the command. The target must run a compatible Worker and already be initialized. Collection never initializes a source, deploys anything, changes billing or executes actions.

```sh
npm run cloudflare:organization-export -- collect OPERATOR_CONFIG.json my-organization /private-backups/new-bundle --local
npm run cloudflare:organization-export -- verify /private-backups/new-bundle my-organization INDEPENDENT_CHECKPOINT_DIGEST
```

Use `--remote` only for an authorized remote collection, with `remote: true` in the operator binding. Omit the final digest in `verify` for content-only verification. Collect prints only organization, checkpoint digest, bundle checksum, action count/cut, `sourceClosed` and `transportClosed`; verify prints the same content metadata without cleanup fields. `sourceClosed: false` means the close acknowledgement was not confirmed; it does not invalidate an otherwise sealed bundle. The source session expires without further valid reads. `transportClosed: false` means local Wrangler disposal or temporary configuration removal was not confirmed. Each cleanup wait is bounded to10seconds and neither discards a successfully sealed bundle. This bounds caller waiting, not termination of a hung Wrangler child process; inspect local resources separately when cleanup is unconfirmed. Keep an independent copy of the checkpoint digest and protect the directory as sensitive backup material.

Collection admits one operator-bound session per live source. Begin captures a fixed cut; component parts contain at most256KiB decoded bytes. The client checks exact length/hash, canonical base64 and UTF-8 JSON, original component limits and complete history before sealing. Invalid responses or deadlines stop local continuation; no automatic retry or partial-directory adoption occurs. Successful reads renew a30-second idle deadline within a one-hour session lifetime. Source restart or failure invalidates its sessions. The generic `cloudflare:owner` CLI refuses these export commands so it cannot print backup bodies; use the collector above.

For internal integrations, the underlying bundle library still accepts validated reader callbacks:

```js
import {
  collectOrganizationBundle,
  verifyOrganizationBundle,
} from './organization-bundle.mjs';

const bundle = await collectOrganizationBundle({
  directory: '/private-backups/new-bundle', // must not exist
  organization: 'my-organization',
  capture: () => reader.capture(),
  readPage: (manifest, options) => reader.readPage(manifest, options),
});

await verifyOrganizationBundle('/private-backups/new-bundle', {
  organization: 'my-organization',
  expectedDigest: bundle.checkpoint.digest,
});
```

`capture()` returns a coordinated checkpoint. `readPage(manifest, {section, cursor})` returns its exact manifest digest, section and bounded page. The collector pins the initial view. The new private export session retains that view after later action/control updates; the older direct `recoveryPage()` API still conflicts after control-head changes. Every action audit sequence through the captured cut must occur exactly once; authority and administrative verifiers require complete ordered history, including unresolved administrative attempts. No durable source state is modified and no action is executed.

The destination uses mode 0700 and files use 0600. Separate lifecycle, trust, authority and administrative files preserve the original per-component validation limits; section-prefixed files contain action records and bounded control history pages. The final `manifest.json` binds every file's bytes and is written after their synchronization. Reader/validation deadlines reject late completion without resuming collection. Existing destinations are never overwritten; a failed collection leaves partial files for investigation. Use a new path for a subsequent attempt.

Offline verification checks canonical UTF-8 JSON, regular protected files, exact inventory, all component checksums and configuration agreements, complete histories and the final file checksum. Supplying a separately retained `expectedDigest` detects replacement by a different internally consistent checkpoint. Taking that value from an untrusted bundle itself adds no authenticity or freshness. Collection can fail after final bytes become visible; successful later content verification does not prove the earlier fsync succeeded. Protect backup custody separately: action arguments, results and identity/administrative history remain sensitive even though runtime credentials are excluded.

This artifact preserves one cut. It cannot protect later acknowledgements, prove an independent failure boundary, establish continuity across successive organization bundles, or activate a restored database. The [organization restore library](ORGANIZATION_RESTORE.md) reconstructs this complete cut in a permanently fenced candidate. Independent journal receipt gating, current-journal reconciliation and external execution fencing remain required. Keycloak state, secret custody and real MCP-side effects are outside these files.

Run `npm run test:cloudflare` and `npm run typecheck:cloudflare`. The [contract and evidence](../../../spec/cloudflare-organization-bundle.md) distinguish local validation from the remaining [production gates](../../../PRODUCTION_READINESS.md).
