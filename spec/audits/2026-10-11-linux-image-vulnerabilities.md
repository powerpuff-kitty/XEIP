# Linux organization image vulnerability assessment

Date: 11 October 2026. Owner: codex. Scope: the unpublished Linux/amd64 organization image from the current uncommitted worktree. This assessment does not cover the Cloudflare deployment, PostgreSQL/Keycloak images, host kernel, independently reviewed cryptography or production configuration.

## Inputs and isolation

- Baseline target: `xeip-organization:local-corruption-review`, image ID `sha256:dc21f4a04758e1649adecd328269c93405ea172943f492c90e6e2e33d2803621`, Alpine 3.24.2 / Node 22.23.3.
- Scanner: Grype 0.120.1, Linux/amd64, Syft 1.54.1, schema 6. Image pinned to `anchore/grype@sha256:e4a44ef45d285b829ce6efe2642980329661bd2d18eab5fc539138d4adaebbbe`. Version output identifies commit `6f8d854af29d3a3086b11a84afa51554a2a245fe` and build time `2026-10-06T20:41:29Z`. The digest pins registry-delivered bytes; a separate publisher signature verification has not been performed.
- Public advisory database download runs in a separate non-root, read-only container with dropped capabilities and no repository/image mount. The image is exported by exact ID, then scanned through a read-only archive mount with networking disabled, no Docker socket and no host credentials. Only the public advisory cache is shared between these steps. The first macOS bind-mounted cache attempt was stopped during prolonged index creation (exit 2); it is not scan evidence. The retry uses Docker-local volume `xeip-grype-db-20261011-42k5h0`, preserving the original partial cache and logs.
- Local evidence directory: `/tmp/xeip-image-vulnerabilities.42k5H0`; pointer `/tmp/xeip-image-vulnerabilities.path`. Preserve raw output and failed attempts. These temporary files are local evidence, not a published release attestation.

## Result

The scoped assessment is complete; remediation is **incomplete**. The final image passes the High-severity scanner threshold and isolated artifact smoke, but retains three Medium package matches and a separately confirmed bundled-library concern. This is not a clean security assessment or production approval.

| Image stage                                     | High | Medium | Low | Total matches | Scan exit |
| ----------------------------------------------- | ---: | -----: | --: | ------------: | --------: |
| Baseline                                        |   20 |     22 |   9 |            51 |         2 |
| zlib revision only                              |   19 |     22 |   9 |            50 |         2 |
| Shared-library updates and runtime tool removal |    0 |      3 |   0 |             3 |         0 |

Counts are package/advisory matches, not distinct vulnerabilities. All three scans use Grype 0.120.1 and the same validated database, schema `v6.1.10`, built `2026-10-11T06:30:42Z`. The downloaded database archive SHA-256 is `a1e7eb21958172e46e2bb6db02e72d68eb4efd4b17d0c43fba5e56ae73d0a196`. Database hash/freshness validation remained enabled. No project-specific exclusions, VEX or suppressions were added; Grype's built-in matcher rules remain in effect. The final squashed-filesystem scan catalogs 48 packages. Earlier base layers and build-stage tooling are outside this runtime scan.

Final unpublished image: `xeip-organization:local-image-security-review`, ID `sha256:0d2d9a60306d0df94625504723bb2071659dd873d781a56ec06a7cbe45f4471d`, 69,883,480 bytes. Exported archive SHA-256: `22aff2796458cf45c745b803e0732bc194ea426cd986ee7f36686235023df565`.

The durable [structured finding inventory](2026-10-11-linux-image-findings.json) preserves every baseline/intermediate/final match, package version, location, severity, fix metadata, database identity, image/archive identity and raw-report hash. Raw `baseline-scan`, `patched-scan` and `final-scan` JSON/log/exit files remain in the local evidence directory. There are no application-level exploitability claims based solely on matching a version.

### Confirmed package finding: CVE-2026-85091

The old image's installed package database contains `zlib 1.3.2-r0`. Alpine's [3.24 main security database](https://secdb.alpinelinux.org/v3.24/main.json) and [package source](https://github.com/alpinelinux/aports/blob/3.24-stable/main/zlib/APKBUILD) identify `1.3.2-r1` as the security revision. Its [patch](https://github.com/alpinelinux/aports/blob/3.24-stable/main/zlib/CVE-2026-85091.patch) applies upstream commit `df84af25dc1942490e1d1c899a07619152a46148`, repairing retained buffer state after a failed nonblocking gzip write. The [CNA advisory](https://www.vulncheck.com/advisories/zlib-1.3.1.2-through-1.3.2-heap-buffer-overflow-via-gz-vacate) describes a heap overflow with stalled nonblocking gzip writes and subsequent formatted writes. Package presence is confirmed; application-level reachability/exploitability has not been demonstrated.

The current `node:22-alpine` tag still resolves to the recorded base digest, so changing the tag alone would not remediate it. The first fix installs `zlib=1.3.2-r1` through Alpine's signed package mechanism, with all three image stages inheriting that base. No signature bypass or custom C patch. Exact version availability is required; future removal from the rolling Alpine repository must fail the build and trigger a reviewed pin update. This is not a permanent package-mirror/provenance solution.

The actual-image regression rejects the old image with `CVE-2026-85091 patched Alpine package` (`/tmp/xeip-image-zlib-red-corrected.log`, exit 1). An earlier probe incorrectly expected `apk info -v zlib` to print a version; its failure is retained in `/tmp/xeip-image-zlib-red.log` but is not valid regression evidence. The corrected check reads the installed APK database directly. The replacement image is `xeip-organization:local-zlib-review`, ID `sha256:25cd1bf39e0246bd6108bcde76fa9c9dc07474aacfc8420f268d0a55505f70f4` (67,407,234 bytes). The replacement build exits 0 (`/tmp/xeip-image-zlib-build.log`). The rebuilt image passes the installed-package assertion and all existing isolated integrity/inventory, runtime/maintenance imports, asynchronous trust-worker and redacted missing-configuration checks (`/tmp/xeip-image-zlib-green.log`, exit 0). The fresh-context scoped reviewer found no defects in the shared-base pin or assertion; it inspected logs and syntax without rerunning Docker. The same-database intermediate scan removes exactly the zlib package match; 50 other matches remained at that point.

The independent platform inventory contains 18 APK packages and reports Node's bundled zlib as `1.3.1-e00f703`. Updating Alpine's shared zlib is not a claim that Node's bundled components were upgraded or exhaustively assessed.

### Shared TLS libraries and unnecessary runtime tools

The baseline contains 26 matches against `libcrypto3`/`libssl3` 3.5.8-r0 (13 distinct CVEs, counted once per library). The [OpenSSL September advisory](https://openssl-library.org/news/secadv/20260929.txt) identifies fixes in 3.5.9; the [Alpine package source](https://raw.githubusercontent.com/alpinelinux/aports/3.24-stable/main/openssl/APKBUILD) supplies 3.5.9-r0. Both exact signed revisions now install in the shared base. Scanner severity can differ from upstream severity; no lower upstream rating was used to suppress a match.

Another 21 matches (11 High) were all in global npm's dependencies under `/usr/local/lib/node_modules/npm`, not XEIP's `/opt/xeip` dependencies. For example, the [picomatch maintainer advisory](https://github.com/micromatch/picomatch/security/advisories/GHSA-c2c7-rcm5-vvqj) identifies the installed 4.0.3 release as affected. The runtime does not need npm, Yarn or Corepack: remove their global installations and launcher paths from the final filesystem while retaining application dependencies and build-stage tools. The scanner confirms all 47 shared-library/global-tool matches disappear from the final runtime. It does not certify build-time package-manager dependencies or erase files from inherited lower image layers.

The actual-image regression fails against the zlib-only image with both outdated TLS packages and global-tool paths (`/tmp/xeip-image-runtime-packages-red.log`, exit 1). The rebuilt final image passes exact package assertions, absence of global tool directories/launchers, immutable non-root inventory/integrity, runtime/maintenance imports, asynchronous worker and redacted missing-configuration checks (`/tmp/xeip-image-runtime-packages-green.log`, exit 0). Build log: `/tmp/xeip-image-runtime-packages-build.log`, exit 0. The second scoped review found no defects in this packaging/test delta.

### Open findings and release conditions

| Finding                                | Evidence and scope                                                                                                                                                                                                                                                                                                                           | Required disposition                                                                                                                                                                                                                                         |
| -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| BusyBox CVE-2025-60876, scanner Medium | Three matches against `busybox`, `busybox-binsh` and `ssl_client` 1.37.0-r31 represent one upstream advisory. No fix version is supplied by this database. A benign control request succeeds; a synthetic raw-CRLF URL passed to the actual `/bin/busybox wget` sends the injected `X-XEIP-Probe` header bytes to a loopback capture server. | Obtain a maintained vendor fix or reviewed runtime replacement, then rerun the probe and image assessment. Application reachability and subpackage attribution require separate analysis. Do not suppress the entire advisory or infer risk acceptance.      |
| Node's bundled OpenSSL 3.5.8           | The final image reports `process.versions.openssl=3.5.8` and `node_shared_openssl=false`. Installing shared Alpine 3.5.9 does not patch this copy. The official Node release index checked on 11 October lists Node 22.23.3 and 24.21.0 with 3.5.8; Node 26.11.1 reports 3.5.9.                                                              | Complete Node/build-specific applicability review and obtain a maintained compatible patched runtime. Do not claim the final zero-High package count covers statically bundled libraries, or silently move to non-LTS Node 26 to remove the version concern. |
| Build and release supply chain         | npm remains available in build/assembly stages; the runtime scan excludes their dependency graph and inherited deleted files. Signed image provenance, scanner publisher verification and hosted image-scan enforcement are not established.                                                                                                 | Assess build inputs separately, preserve release evidence and verify hosted CI execution and release enforcement before publishing.                                                                                                                                            |

The BusyBox probe used no external network, real credentials, application requests or privileged container capabilities. Its five-second bound and a successful benign control distinguish request-byte behavior from connection failure. `runtime-residual-probe.json` and the structured inventory retain the exact synthetic capture. This confirms unsafe behavior in the installed utility, not exploitability through XEIP. Primary references: [BusyBox advisory record](https://nvd.nist.gov/vuln/detail/CVE-2025-60876), [Alpine BusyBox packaging](https://raw.githubusercontent.com/alpinelinux/aports/3.24-stable/main/busybox/APKBUILD), [Node release index](https://nodejs.org/dist/index.json). No version change or exception was applied for these residuals.

## Sources and interpretation

[Grype 0.120.1 release](https://github.com/anchore/grype/releases/tag/v0.120.1), [supported archive targets](https://oss.anchore.com/docs/guides/vulnerability/scan-targets/), [database management](https://oss.anchore.com/docs/guides/vulnerability/database/) and [configuration reference](https://oss.anchore.com/docs/reference/grype/configuration/).

The scan uses published package/advisory matches, not exploit testing. Keep database integrity and freshness checks enabled. An empty report would mean no matches in this scanner/database scope, not absence of vulnerabilities. Hosted CI, signed provenance, maintained releases and broader release acceptance remain separate gates.

## Reproduction

### Automated gate verification

The repeatable command is verified separately from the image remediation above. Report-policy regressions first failed 5/5 against a success-only stub; the added source-metadata regression then failed 1/6 before sanitization. Final unit verification passes 6/6 and the root suite passes 384/384 (`/tmp/xeip-image-scan-gate-green.log`, `/tmp/xeip-image-scan-gate-root-tests-final.log`). Workflow YAML parses; hosted Actions execution has not occurred.

The scoped review found that raw Grype JSON includes encoded image configuration. The command now strips source metadata to image/manifest digests before retention; the reviewer found no remaining issues in that delta. Raw output is confined to owned temporary storage, outside the CI upload selection.

Preserve but exclude the first wrapper attempts (`/tmp/xeip-image-scan-gate-baseline*` and `/tmp/xeip-image-scan-gate-final*` without the `-verified` suffix): edits to a running shell file caused parser/command errors. Baseline shell exit 2 was **not** valid threshold evidence; the fresh-cache attempt exited 127. Neither is accepted as a successful command validation. The baseline's Docker scan still produced its own raw report, but the wrapper result cannot prove the gate. Corrected runs freeze source files and check their hashes before accepting evidence.

| Final command check                                 | Result                                                                                                                                              | Local evidence                                 |
| --------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------- |
| Known vulnerable baseline                           | Grype, policy and command all exit 2; retained counts High 20 / Medium 22 / Low 9                                                                   | `/tmp/xeip-image-scan-gate-baseline-verified/` |
| Remediated runtime, existing validated public cache | Grype, policy and command all exit 0; three Medium findings retained                                                                                | `/tmp/xeip-image-scan-gate-final-verified/`    |
| Remediated runtime, new public cache                | Grype, policy and command all exit 0; three Medium findings retained; owned cache removed and source hashes unchanged                               | `/tmp/xeip-image-scan-gate-fresh-verified/`    |
| Missing image                                       | Exit 1 before scan; no vulnerability report manufactured                                                                                            | `/tmp/xeip-image-scan-gate-missing-verified/`  |
| CLI error boundary                                  | Rejects scanner exits 1/2/137, invalid status and malformed JSON; valid reports retain findings with only image/manifest digests in source metadata | `/tmp/xeip-image-scan-policy-cli.log`          |

All three final native reports use a valid database and retain only `imageID`/`manifestDigest` in `source.target`. Their source hashes remain unchanged across the runs: shell command `015f6e694c8a865a0c2ad2fffff71d0dae95ee0af21960e91e99d4b00286d745`, report policy `2e84daeda55b8dde3f914bfc2a788e133cb8dc704ac9e152e30cbf20db932d1a`. The fresh-cache path downloads/prepares the public database, scans offline and removes its owned volume; Docker confirms that volume no longer exists. The supplied shared public cache remains present. Retained evidence contains neither an image archive nor raw JSON. This proves the local command paths; actual GitHub execution/upload and release acceptance remain unverified.

The maintained [image scan command](../organization-artifact.md#repeatable-image-vulnerability-gate) automates this boundary, validates the report and strips encoded image configuration before CI retention. The commands below preserve the original manual assessment procedure; their raw `scan.json` can include image configuration and must not be uploaded without sanitizing its source metadata.

Run with Docker available and the exact target image already built. Commands download public scanner/advisory data, but do not upload the image. Use a private directory and retain reports. Image changes require a new assessment; substituting a current tag for the recorded image ID would assess different bytes.

```sh
set -eu
scanner='anchore/grype@sha256:e4a44ef45d285b829ce6efe2642980329661bd2d18eab5fc539138d4adaebbbe'
target='sha256:0d2d9a60306d0df94625504723bb2071659dd873d781a56ec06a7cbe45f4471d'
evidence=$(mktemp -d)
cache_volume="xeip-grype-db-$(date +%s)"
docker volume create "$cache_volume"
# Initialize only this new cache volume for the scanner UID.
docker run --rm --network none --read-only --cap-drop=ALL \
  --security-opt no-new-privileges --user 0:0 \
  --mount "type=volume,src=$cache_volume,dst=/db" \
  --entrypoint node "$target" -e 'require("node:fs").chmodSync("/db",0o777)'
docker pull "$scanner"
docker save --output "$evidence/image.tar" "$target"
chmod 444 "$evidence/image.tar"
docker run --rm --read-only --cap-drop=ALL --security-opt no-new-privileges \
  --user 1000:1000 --tmpfs /tmp:rw,nosuid,nodev,mode=1777 \
  --mount "type=volume,src=$cache_volume,dst=/db" \
  -e GRYPE_DB_CACHE_DIR=/db -e GRYPE_CHECK_FOR_APP_UPDATE=false \
  "$scanner" db update -v > "$evidence/db-update.log" 2>&1
docker run --rm --network none --read-only --cap-drop=ALL \
  --security-opt no-new-privileges --user 1000:1000 \
  --tmpfs /tmp:rw,nosuid,nodev,mode=1777 \
  --mount "type=volume,src=$cache_volume,dst=/db,readonly" \
  --mount "type=bind,src=$evidence/image.tar,dst=/image.tar,readonly" \
  -e GRYPE_DB_CACHE_DIR=/db -e GRYPE_DB_AUTO_UPDATE=false \
  -e GRYPE_CHECK_FOR_APP_UPDATE=false \
  "$scanner" docker-archive:/image.tar --scope squashed --output json --fail-on high -vv \
  > "$evidence/scan.json" 2> "$evidence/scan.log"
```

A nonzero scan exit must be investigated: it can indicate a severity threshold failure or a scanner/database error. Do not translate every nonzero exit into a vulnerability count, discard the JSON, add blanket exclusions, or disable database validation to obtain a pass.
