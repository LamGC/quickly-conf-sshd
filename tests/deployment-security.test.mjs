import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFile, mkdtemp, mkdir, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {verifyCommitSignature, enabledFlag, parseFingerprints, verifySignatureStatus} from '../scripts/verify-commit-signature.mjs';
import {notifyDeployment, deploymentPayload} from '../scripts/notify-deployment.mjs';
import {openPgpFixture} from './helpers/openpgp-fixture.mjs';

const primary = 'A'.repeat(40), subkey = 'B'.repeat(40);
const validStatus = (fingerprint = primary, signer = fingerprint) => `[GNUPG:] GOODSIG 1234567890ABCDEF Test fixture\n[GNUPG:] VALIDSIG ${signer} 2026-01-01 1767225600 0 4 0 22 8 00 ${fingerprint}\n`;

test('GPG opt-in is strict and only accepts complete primary fingerprint pins', () => {
  for (const value of [undefined,'','false']) assert.equal(enabledFlag(value),false);
  assert.equal(enabledFlag('true'),true);
  for (const value of ['TRUE','yes','1',' false ','False',null]) assert.throws(() => enabledFlag(value));
  assert.deepEqual(parseFingerprints(primary.toLowerCase()+',\n'+subkey),new Set([primary,subkey]));
  for (const value of ['',undefined,'1234ABCD','A'.repeat(64),primary+' invalid']) assert.throws(() => parseFingerprints(value));
});

test('machine status requires a pinned primary and rejects bad, expired and revoked signatures', () => {
  const pins = new Set([primary]);
  assert.deepEqual(verifySignatureStatus(validStatus(primary,subkey),pins),{signerFingerprint:subkey,primaryFingerprint:primary});
  assert.throws(() => verifySignatureStatus(validStatus(subkey),pins),/not pinned/);
  assert.throws(() => verifySignatureStatus('[GNUPG:] GOODSIG 123 Test fixture\n',pins),/exactly one/);
  assert.throws(() => verifySignatureStatus(validStatus()+validStatus(),pins),/exactly one/);
  for (const code of ['BADSIG','ERRSIG','NO_PUBKEY','EXPSIG','EXPKEYSIG','REVKEYSIG','KEYEXPIRED','SIGEXPIRED','KEYREVOKED','FAILURE','ERROR','NODATA','BADARMOR']) {
    assert.throws(() => verifySignatureStatus(validStatus()+`[GNUPG:] ${code} rejected\n`,pins),/invalid, expired, revoked/);
  }
  assert.throws(() => verifySignatureStatus(validStatus().replace('1767225600 0 4','1767225600 1767225601 4'),pins,1767225602),/expired/);
  assert.throws(() => verifySignatureStatus(validStatus().replace('22 8 00','22 2 00'),pins),/SHA-256/);
  assert.throws(() => verifySignatureStatus(validStatus().replace(' 4 0 22',' 5 0 22'),pins),/v4/);
  assert.throws(() => verifySignatureStatus(validStatus().replace(` 00 ${primary}`,' 00'),pins),/primary fingerprint/);
});

function command(bin,args,options = {}) {
  const result = spawnSync(bin,args,{encoding:'utf8',timeout:30_000,...options});
  assert.equal(result.error,undefined,`${bin} failed to execute`);
  assert.equal(result.status,0,`${bin} failed: ${result.stderr}`);
  return result.stdout;
}

test('GPG gate verifies real ephemeral Git commits in an isolated keyring', {timeout:120_000}, async t => {
  const directory = await mkdtemp(join(tmpdir(),'conf-sshd-signature-test-'));
  const repo = join(directory,'repo');await mkdir(repo);
  const env = {...process.env,GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null'};
  const git = (args,options = {}) => command('git',args,{cwd:repo,env,...options});
  const commit = (name,fixture) => {
    const tree = git(['hash-object','-t','tree','-w','--stdin'],{input:''}).trim();
    const headers = `tree ${tree}\nauthor Security fixture <fixture@example.invalid> 1767225600 +0000\ncommitter Security fixture <fixture@example.invalid> 1767225600 +0000`;
    const body = `${headers}\n\n${name}\n`;
    const signed = fixture ? `${headers}\ngpgsig ${fixture.sign(body).trimEnd().replaceAll('\n','\n ')}\n\n${name}\n` : body;
    const sha = git(['hash-object','-t','commit','-w','--stdin'],{input:signed}).trim();
    git(['update-ref','HEAD',sha]);return sha;
  };
  const gateEnv = (sha,pin,key) => ({...env,GITHUB_SHA:sha,REQUIRE_GPG_SIGNATURE:'true',GPG_ALLOWED_PRIMARY_FINGERPRINTS:pin,GPG_PUBLIC_KEYS:key});
  try {
    git(['init','-q']);
    const good = openPgpFixture(), other = openPgpFixture(), sub = openPgpFixture({subkeys:2});
    let sha = commit('unsigned fixture');
    await t.test('disabled still pins HEAD; enabled unsigned/missing config/incorrect SHA fail',async () => {
      assert.equal((await verifyCommitSignature({env:{...env,GITHUB_SHA:sha},directory:repo})).required,false);
      await assert.rejects(verifyCommitSignature({env:{...env,GITHUB_SHA:'0'.repeat(40)},directory:repo}),/does not match/);
      await assert.rejects(verifyCommitSignature({env:{...env,GITHUB_SHA:sha,REQUIRE_GPG_SIGNATURE:'invalid'},directory:repo}),/exactly true/);
      await assert.rejects(verifyCommitSignature({env:{...env,GITHUB_SHA:sha,REQUIRE_GPG_SIGNATURE:'true'},directory:repo}),/FINGERPRINTS/);
      await assert.rejects(verifyCommitSignature({env:gateEnv(sha,good.primaryFingerprint,''),directory:repo}),/public keys/);
      await assert.rejects(verifyCommitSignature({env:gateEnv(sha,good.primaryFingerprint,good.publicKey),directory:repo}),/Git verification command failed/);
    });
    sha = commit('approved signature fixture',good);
    await t.test('approved primary passes; wrong pin, missing public signer and Git nonzero fail',async () => {
      assert.equal((await verifyCommitSignature({env:gateEnv(sha,good.primaryFingerprint,good.publicKey),directory:repo})).primaryFingerprint,good.primaryFingerprint);
      assert.equal((await verifyCommitSignature({env:gateEnv(sha,`${other.primaryFingerprint},${good.primaryFingerprint}`,other.publicKey+good.publicKey),directory:repo})).primaryFingerprint,good.primaryFingerprint);
      await assert.rejects(verifyCommitSignature({env:gateEnv(sha,other.primaryFingerprint,good.publicKey),directory:repo}),/not pinned/);
      await assert.rejects(verifyCommitSignature({env:gateEnv(sha,good.primaryFingerprint,other.publicKey),directory:repo}),/Git verification command failed/);
      await assert.rejects(verifyCommitSignature({env:gateEnv(sha,good.primaryFingerprint,good.publicKey),directory}),/Git verification command failed/);
    });
    sha = commit('tampered commit fixture',{sign:data=>good.sign(data.replace('tampered commit fixture','original commit fixture'))});
    await t.test('a valid signature on different commit bytes is rejected',async () => {
      await assert.rejects(verifyCommitSignature({env:gateEnv(sha,good.primaryFingerprint,good.publicKey),directory:repo}),/Git verification command failed/);
    });
    sha = commit('signing subkey fixture',sub);
    await t.test('signing subkey is accepted only through the pinned primary fingerprint',async () => {
      const result = await verifyCommitSignature({env:gateEnv(sha,sub.primaryFingerprint,sub.publicKey),directory:repo});
      assert.equal(result.primaryFingerprint,sub.primaryFingerprint);assert.equal(result.signerFingerprint,sub.signerFingerprint);assert.notEqual(result.signerFingerprint,sub.primaryFingerprint);
      await assert.rejects(verifyCommitSignature({env:gateEnv(sha,sub.signerFingerprint,sub.publicKey),directory:repo}),/not pinned/);
      const secondSha = commit('second signing subkey fixture',{sign:data=>sub.sign(data,1)});
      const second = await verifyCommitSignature({env:gateEnv(secondSha,sub.primaryFingerprint,sub.publicKey),directory:repo});
      assert.equal(second.primaryFingerprint,sub.primaryFingerprint);assert.equal(second.signerFingerprint,sub.signerFingerprints[1]);
    });
    const revoked = openPgpFixture({revoked:true});sha = commit('revoked fixture',revoked);
    await t.test('real primary revocation rejects a previously created signature',async () => {
      await assert.rejects(verifyCommitSignature({env:gateEnv(sha,revoked.primaryFingerprint,revoked.publicKey),directory:repo}),/Git verification command failed|revoked/);
    });
    const expired = openPgpFixture({expired:true});sha = commit('expired key fixture',expired);
    await t.test('expired signing key is rejected using current verifier time',async () => {
      await assert.rejects(verifyCommitSignature({env:gateEnv(sha,expired.primaryFingerprint,expired.publicKey),directory:repo}),/Git verification command failed|expired/);
    });
    sha = commit('forced verifier fixture',good);
    await t.test('Git configuration cannot substitute another signature format or verifier',async () => {
      git(['config','gpg.format','ssh']);git(['config','gpg.openpgp.program','/bin/true']);git(['config','gpg.program','/bin/true']);
      assert.equal((await verifyCommitSignature({env:gateEnv(sha,good.primaryFingerprint,good.publicKey),directory:repo})).primaryFingerprint,good.primaryFingerprint);
    });
  } finally {await rm(directory,{recursive:true,force:true});}
});

const notificationEnv = {
  ENABLE_MAIL_NOTIFICATION:'true',CI:'true',GITHUB_ACTIONS:'true',
  MAIL_NOTIFICATION_WEBHOOK:'https://mailer.example.invalid/hook?token=DO_NOT_LOG',
  MAIL_NOTIFICATION_TO:'owner@example.invalid',DEPLOYMENT_STATUS:'success',DEPLOYMENT_PHASE:'complete',
  GITHUB_SHA:'c'.repeat(40),GITHUB_REPOSITORY:'example/server-keys',GITHUB_RUN_ID:'123',
};
const deploymentConfig = {
  baseUrl:'https://ssh.example.invalid',keySource:{type:'gist'},
  signedRelease:{listId:'server-keys-production'},fallbackSources:['https://backup.example.invalid/server.keys'],
};

test('notification stays network-free unless explicitly enabled in CI with complete configuration',async () => {
  let calls = 0;const fetchImpl = async () => {calls++;return {ok:true,status:200};};
  for (const ENABLE_MAIL_NOTIFICATION of [undefined,'','false']) {
    assert.deepEqual(await notifyDeployment({env:{ENABLE_MAIL_NOTIFICATION},fetchImpl}),{sent:false,reason:'disabled'});
  }
  for (const value of ['yes','TRUE','1']) await assert.rejects(notifyDeployment({env:{...notificationEnv,ENABLE_MAIL_NOTIFICATION:value},config:deploymentConfig,fetchImpl}),/exactly true/);
  await assert.rejects(notifyDeployment({env:{...notificationEnv,CI:'false'},config:deploymentConfig,fetchImpl}),/only in GitHub Actions/);
  await assert.rejects(notifyDeployment({env:{...notificationEnv,MAIL_NOTIFICATION_WEBHOOK:''},config:deploymentConfig,fetchImpl}),/required/);
  for (const endpoint of ['http://mailer.example.invalid','https://user:password@mailer.example.invalid','https://mailer.example.invalid/#secret']) {
    await assert.rejects(notifyDeployment({env:{...notificationEnv,MAIL_NOTIFICATION_WEBHOOK:endpoint},config:deploymentConfig,fetchImpl}),/HTTPS/);
  }
  assert.equal(calls,0);
});

test('notification JSON identifies deployment, configured mode/list/fallbacks and uses a bounded nonredirecting POST',async () => {
  for (const [status,phase] of [['success','complete'],['failure','deployment'],['failure','remote-verification']]) {
    const result = await notifyDeployment({env:{...notificationEnv,DEPLOYMENT_STATUS:status,DEPLOYMENT_PHASE:phase},config:deploymentConfig,fetchImpl:async (url,options) => {
      assert.equal(url,notificationEnv.MAIL_NOTIFICATION_WEBHOOK);assert.equal(options.method,'POST');assert.equal(options.redirect,'error');
      assert.equal(options.headers['content-type'],'application/json');assert.ok(options.signal instanceof AbortSignal);
      const payload = JSON.parse(options.body);
      assert.equal(payload.status,status);assert.equal(payload.phase,phase);assert.equal(payload.revision,notificationEnv.GITHUB_SHA);
      assert.equal(payload.configuration.mode,'gist');assert.equal(payload.configuration.listId,'server-keys-production');
      assert.deepEqual(payload.configuration.fallbackSources,deploymentConfig.fallbackSources);assert.match(payload.configurationScope,/not measured server state/);
      assert.equal(payload.to,'owner@example.invalid');assert.ok(!options.body.includes('DO_NOT_LOG'));
      return {ok:true,status:202};
    }});
    assert.deepEqual(result,{sent:true});
  }
  const defaults = deploymentPayload({baseUrl:'https://ssh.example.invalid'}, {...notificationEnv,MAIL_NOTIFICATION_TO:''});
  assert.equal(defaults.configuration.mode,'git');assert.equal(defaults.configuration.listId,null);assert.equal(defaults.to,null);
  assert.deepEqual(defaults.configuration.fallbackSources,[]);
});

test('notification rejects ambiguous metadata and never exposes webhook tokens or retries failures',async () => {
  for (const patch of [{DEPLOYMENT_STATUS:'unknown'},{DEPLOYMENT_PHASE:'unknown'},{GITHUB_SHA:'main'},{GITHUB_REPOSITORY:'evil\nrepo'},{GITHUB_RUN_ID:'$((1))'},{MAIL_NOTIFICATION_TO:'a@example.invalid\nBcc:b@example.invalid'}]) {
    assert.throws(() => deploymentPayload(deploymentConfig,{...notificationEnv,...patch}));
  }
  let calls = 0;
  await assert.rejects(notifyDeployment({env:notificationEnv,config:deploymentConfig,fetchImpl:async () => {calls++;throw Error(notificationEnv.MAIL_NOTIFICATION_WEBHOOK);}}),error=>!error.message.includes('DO_NOT_LOG') && /request failed/.test(error.message));
  assert.equal(calls,1);
  await assert.rejects(notifyDeployment({env:notificationEnv,config:deploymentConfig,fetchImpl:async () => ({ok:false,status:503})}),/HTTP 503/);
});

test('deployment workflow gates both entry points before repository execution and separates secret scopes',async () => {
  const workflow = await readFile(new URL('../.github/workflows/deploy.yml',import.meta.url),'utf8');
  const verify = workflow.split('\n  verify:\n')[1].split('\n  deploy:\n')[0];
  const deploy = workflow.split('\n  deploy:\n')[1].split('\n  notify:\n')[0];
  const notify = workflow.split('\n  notify:\n')[1];
  assert.match(workflow,/workflow_dispatch:/);assert.match(verify,/refs\/heads\/main/);assert.match(verify,/verify-commit-signature\.mjs/);
  assert.ok(!verify.includes('${{ secrets.'));assert.ok(!verify.includes('environment: production'));assert.ok(!verify.includes('npm '));
  assert.match(deploy,/needs: verify/);assert.match(deploy,/environment: production/);
  assert.equal((workflow.match(/ref: \$\{\{ github.sha \}\}/g)||[]).length,3);
  assert.match(notify,/needs\.deploy\.outputs\.attempted == 'true'/);assert.ok(!notify.includes('CLOUDFLARE_'));
  assert.match(notify,/DEPLOYMENT_PHASE:/);assert.match(notify,/MAIL_NOTIFICATION_WEBHOOK/);
});
