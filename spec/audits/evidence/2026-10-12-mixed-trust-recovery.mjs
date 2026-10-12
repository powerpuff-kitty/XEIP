// Disposable investigation, not a passing production acceptance test.
import assert from 'node:assert/strict';
import { randomBytes, createPublicKey } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('../../../', import.meta.url)).replace(/\/$/, '');
const { withPostgres } = await import(root + '/conformance/postgres.mjs');
const { EntityTrustPolicy } = await import(root + '/services/relay/entity-trust.mjs');
const { ActionPolicy, PolicyDenied } = await import(root + '/services/organization/actions.mjs');
const { ActionStore } = await import(root + '/services/organization/store.mjs');
const { liveActionAuthorizer } = await import(root + '/services/organization/authorization.mjs');
const { createActionExecutor } = await import(root + '/services/organization/execution.mjs');
const { encodeKeyId } = await import(root + '/packages/identity/key-id.mjs');
const { ed25519PrivateKeyFromSeed } = await import(root + '/packages/identity/signed-envelope.mjs');
const { signKeyDocument } = await import(root + '/packages/identity/key-document.mjs');
const { signStatusDocument } = await import(root + '/packages/identity/identity-status.mjs');
const now = () => Math.floor(Date.now() / 1000);
const utc = () => new Date(now()*1000).toISOString().replace('.000Z', 'Z');
function identity(subject, role) {
  const seed = randomBytes(32), device = randomBytes(32);
  const keyId = seed => encodeKeyId(createPublicKey(ed25519PrivateKeyFromSeed(seed)).export({format:'der',type:'spki'}).subarray(-32));
  const rootKid = keyId(seed), kid = keyId(device), entity = 'urn:xeip:entity:' + rootKid;
  const document = signKeyDocument({xeip:'xeip.keydoc/0.1',entity,genesis:rootKid,generation:1,issuedAt:utc(),roots:[rootKid],devices:[kid],signatures:[]}, {privateKey:seed,kid:rootKid});
  const status = (serial, revoked = false) => ({document:signStatusDocument({xeip:'xeip.status/0.1',entity,serial,issuedAt:utc(),revoked:revoked?[{kid,generation:1}]:[],signatures:[]},{privateKey:seed,kid:rootKid})});
  return { principal:Object.freeze({subject,entity,kid,clientId:'probe',roles:Object.freeze([role]),expiresAt:now()+3600}), key:{document,anchor:{genesisKid:rootKid}}, status };
}
await withPostgres(async ({pool}) => {
  const dir=mkdtempSync(join(tmpdir(),'xeip-mixed-trust-probe-'));
  let trust;
  try {
    const agent=identity('probe-agent','agent'), human=identity('probe-human','approver');
    const config={trustDir:join(dir,'trust'),maxAgeSeconds:3600};
    const old={keyDocuments:[agent.key,human.key],statusDocuments:[agent.status(1),human.status(1)]};
    const open=provision=>new EntityTrustPolicy(config,provision.keyDocuments,provision.statusDocuments);
    trust=open(old);
    const oldCheckpoint=readFileSync(join(config.trustDir,'trust.json'));
    const session='urn:xeip:session:mixed-recovery', id='urn:xeip:action:mixed-recovery';
    const policy=new ActionPolicy({targets:[{id:'internal',revision:'1',recipient:human.principal.entity,tools:['lookup']}],sessions:[{id:session,agents:[agent.principal.subject],approvers:[human.principal.subject],targets:['internal']}]});
    const authorize = () => liveActionAuthorizer({revalidate:async()=>true},trust);
    let store=new ActionStore(pool,policy,authorize());
    const proposed=await store.propose(agent.principal,{id,session,target:'internal',tool:'lookup',arguments:{synthetic:true},expiresAt:now()+290});
    const digest=proposed.proposal.digest;
    await store.decide(human.principal,session,id,digest,'approve');
    let effects=0;
    const execute=createActionExecutor(policy,{call:async (_action,{beforeSend})=>{
      assert.equal(await beforeSend(),true); effects++; return {synthetic:true};
    }});
    const snapshot=async()=>({actions:(await pool.query('SELECT * FROM xeip_org.actions ORDER BY request_id')).rows,audit:(await pool.query('SELECT * FROM xeip_org.audit ORDER BY sequence')).rows});
    const beforeRevocation=await snapshot();
    const current={keyDocuments:old.keyDocuments,statusDocuments:[agent.status(2,true),old.statusDocuments[1]]};
    await trust.updateAsync(current);
    assert.equal(trust.allows(agent.principal),false);
    await assert.rejects(execute(agent.principal,{session,id,digest},{store,authorize:authorize()}),PolicyDenied);
    assert.equal(effects,0);
    assert.deepEqual(await snapshot(),beforeRevocation);
    trust.close();
    // Intact high-water state rejects the older still-valid signed provisioning.
    assert.throws(()=>open(old),/rollback/);
    // Model restoring the older checkpoint and provisioning together. No DB rollback.
    writeFileSync(join(config.trustDir,'trust.json'),oldCheckpoint,{mode:0o600});
    trust=open(old);
    assert.equal(trust.allows(agent.principal),true);
    assert.deepEqual(await snapshot(),beforeRevocation);
    store=new ActionStore(pool,policy,authorize());
    await execute(agent.principal,{session,id,digest},{store,authorize:authorize()});
    assert.equal(effects,1);
    console.log(JSON.stringify({finding:'stale-trust-restore-reactivates-revoked-device',intactCheckpointRejectsRollback:true,revokedClaimDenied:true,databaseUnchangedByRevocation:true,restoredOldTrustAllowsDevice:true,syntheticEffects:effects,scope:'real disposable PostgreSQL and signed trust; provider revalidation stub; no HTTP/MCP/network effect; not an acceptance pass'}));
  } finally {trust?.close();rmSync(dir,{recursive:true,force:true});}
},{baselineChecks:false});
