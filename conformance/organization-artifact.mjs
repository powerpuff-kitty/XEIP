// Inspect an already-built local image. Never pulls, publishes or deploys it.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
const image = process.argv[2] ?? "xeip-organization:local-review";
if (!/^[a-z0-9][a-z0-9._/:@-]*$/.test(image))
  throw new Error("invalid image reference");
const isolated = [
  "run",
  "--rm",
  "--pull=never",
  "--network",
  "none",
  "--read-only",
  "--cap-drop=ALL",
  "--security-opt",
  "no-new-privileges",
  "--cpus",
  "1",
  "--memory",
  "256m",
  "--pids-limit",
  "64",
];
const docker = (args) =>
  execFileSync("docker", args, {
    encoding: "utf8",
    timeout: 60000,
    maxBuffer: 4 * 1024 * 1024,
  });
const inspection = JSON.parse(docker(["image", "inspect", image]))[0];
assert.equal(inspection.Architecture, "amd64");
assert.equal(inspection.Os, "linux");
assert.equal(inspection.Config.User, "1000:1000");
assert.deepEqual(inspection.Config.Entrypoint, [
  "node",
  "services/organization/main.mjs",
]);
const result = docker([
  ...isolated,
  "--entrypoint",
  "node",
  image,
  "--input-type=module",
  "-e",
  `
import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync, statSync, accessSync, constants } from 'node:fs';
import { execFileSync } from 'node:child_process';
assert.equal(process.getuid(), 1000);
assert.equal(process.versions.node, '22.23.3');
const installedZlib = readFileSync('/lib/apk/db/installed', 'utf8').split('\\n\\n')
  .find(pkg => pkg.split('\\n').includes('P:zlib'));
assert.ok(installedZlib, 'installed Alpine zlib package');
assert.ok(installedZlib.split('\\n').includes('V:1.3.2-r1'), 'CVE-2026-85091 patched Alpine package');
const platformDefects = [];
const apkRecords = readFileSync('/lib/apk/db/installed', 'utf8').split('\\n\\n');
for (const name of ['libcrypto3', 'libssl3']) {
  const record = apkRecords.find(pkg => pkg.split('\\n').includes('P:' + name));
  if (!record?.split('\\n').includes('V:3.5.9-r0')) platformDefects.push(name + ' must be 3.5.9-r0');
}
for (const path of ['/usr/local/lib/node_modules', '/usr/local/bin/npm', '/usr/local/bin/npx', '/usr/local/bin/corepack', '/usr/local/bin/yarn', '/usr/local/bin/yarnpkg', '/usr/local/bin/pnpm', '/usr/local/bin/pnpx', ...readdirSync('/opt').filter(name => name.startsWith('yarn-')).map(name => '/opt/' + name)]) {
  if (existsSync(path)) platformDefects.push('unused package tool: ' + path);
}
assert.deepEqual(platformDefects, [], 'patched shared TLS libraries and no runtime package managers');
assert.equal(statSync('services/organization/main.mjs').uid, 0);
assert.equal(statSync('services/organization/main.mjs').mode & 0o222, 0);
assert.throws(() => accessSync('services/organization/main.mjs', constants.W_OK));
for (const path of ['.git', 'tools', 'conformance', 'services/organization/test-fixtures', 'services/organization/main.test.mjs', 'services/relay/server.mjs', 'node_modules/typescript', 'node_modules/@modelcontextprotocol/server']) assert.equal(existsSync(path), false, path);
const bom = JSON.parse(readFileSync('sbom.cdx.json','utf8'));
assert.equal(bom.bomFormat,'CycloneDX');
assert.ok(bom.components.some(c => c.name === 'pg'));
assert.ok(bom.components.some(c => c.name === 'jose'));
assert.ok(bom.components.some(c => c.name === 'keycloak-js'));
assert.equal(bom.components.some(c => c.name === 'typescript'), false);
const lock = JSON.parse(readFileSync('source.package-lock.json','utf8'));
for (const [path, dependency] of Object.entries(lock.packages)) {
  if (!path || dependency.dev) continue;
  if (dependency.optional && !existsSync(path + '/package.json')) continue;
  assert.ok(existsSync(path + '/package.json'), 'missing installed package ' + path);
  const installed = JSON.parse(readFileSync(path + '/package.json','utf8'));
  assert.equal(installed.version, dependency.version);
  assert.ok(bom.components.some(c => c.name === installed.name && c.version === installed.version), 'inventory missing ' + installed.name);
}
execFileSync('sha256sum', ['-c', 'files.sha256'], {stdio:'pipe',maxBuffer:4*1024*1024});
await import('./services/organization/main.mjs');
const { loadConsoleAssets } = await import('./services/organization/console-server.mjs');
const assets = loadConsoleAssets();
assert.equal(assets.size, 4);
assert.ok(assets.get('/console/').body.includes('Review before it runs.'));
assert.ok(assets.get('/console/app.js').body.length > 1000);
assert.ok(assets.get('/console/THIRD_PARTY_LICENSES.txt').body.includes('keycloak-js 26.2.4'));
assert.equal(existsSync('dist/console/app.js.map'), false);
assert.equal(existsSync('node_modules/esbuild'), false);
assert.equal(existsSync('node_modules/@playwright/test'), false);
assert.equal(existsSync('services/organization/cloudflare'), false);
assert.equal(existsSync('node_modules/miniflare'), false);
assert.equal(existsSync('node_modules/workerd'), false);
assert.equal(bom.components.some(c => ['miniflare','workerd'].includes(c.name)), false);
await import('./services/organization/maintenance.mjs');
const { parseControlArguments } = await import('./services/organization/control-maintenance.mjs');
assert.deepEqual(parseControlArguments(['inspect','--owner-config','/nonexistent']), {operation:'inspect',ownerPath:'/nonexistent'});
const { prepareEntityTrustInWorker } = await import('./packages/identity/trust-preparation.mjs');
const prepared = await prepareEntityTrustInWorker({maxAgeSeconds:60}, {keyDocuments:[],statusDocuments:[]}, Math.floor(Date.now()/1000), new AbortController().signal);
assert.equal(prepared.bundles.size, 0);
console.log('PASS isolated asynchronous trust worker');
const { publicAuthority } = await import('./services/organization/control-state.mjs');
const { prepareControlInWorker } = await import('./services/organization/control-preparation.mjs');
const entity = 'urn:xeip:entity:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd';
const kid = entity.slice('urn:xeip:entity:'.length);
const target = {id:'internal',revision:'1',recipient:entity,tools:['lookup'],endpoint:'https://tool.test/mcp',resourceMetadataUrl:'https://tool.test/resource',issuer:'https://tool-id.test',tokenEndpoint:'https://tool-id.test/token',clientId:'xeip',clientSecret:'artifact-validation-only',scope:'tools'};
const authority = publicAuthority({origin:'https://xeip.test',gateway:entity,bind:{},tls:{},database:{},management:{},shutdownMs:1000,authentication:{issuer:'https://id.test/realm',audience:'xeip',clientIds:['agent','human'],bindings:['agent','human'].map(subject=>({subject,entity,kid})),introspectionClientId:'xeip',introspectionClientSecret:'artifact-validation-only'},policy:{targets:[{id:target.id,revision:target.revision,recipient:entity,tools:target.tools}],sessions:[{id:'urn:xeip:session:artifact',agents:['agent'],approvers:['human'],targets:['internal']}]},targets:[target],trust:{directory:'/unused',provisioningFile:'/unused',maxAgeSeconds:300},provisioning:{keyDocuments:[],statusDocuments:[]}});
const control = await prepareControlInWorker('prepare',{authority,provisioning:{keyDocuments:[],statusDocuments:[]},retainedRecords:{},operation:'enroll',acceptedAt:Math.floor(Date.now()/1000)});
const verifiedControl = await prepareControlInWorker('verify',control.canonical);
assert.equal(verifiedControl.digest,control.digest);
assert.ok(Object.isFrozen(verifiedControl.state));
console.log('PASS isolated full control preparation and verification worker');
console.log('PASS non-root immutable artifact, dependency inventory, file integrity and runtime/maintenance imports');
`,
]);
console.log(result.trim());
try {
  docker([
    ...isolated,
    image,
    "check",
    "--config",
    "/missing/private-configuration",
  ]);
  assert.fail("incomplete configuration must not start");
} catch (error) {
  assert.equal(error.status, 1);
  const lines = error.stderr
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert.deepEqual(
    lines.map((line) => line.event),
    ["startup_failed"],
  );
  assert.equal(error.stderr.includes("private-configuration"), false);
}
console.log(
  "PASS isolated executable rejects missing configuration with redacted exit 1",
);
