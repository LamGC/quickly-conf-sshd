import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile, mkdtemp, writeFile, rm, cp, mkdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {makeSignedDocument, parseSignedDocument, parseSignedBundle, parsePublishedSignedRelease, SIGNATURE_SEPARATOR, SIGNED_RELEASE_LIMITS, validateSignature} from '../cf-worker/src/signed-release.js';
import {prepare} from '../scripts/prepare-key-release.mjs';
import {openPgpFixture} from './helpers/openpgp-fixture.mjs';
import {verifyRemote} from '../scripts/verify-release.mjs';
import {validateConfig, validateClientDefaults, build, root} from '../scripts/build.mjs';
import {validatePublicCertificate, checkSigningCertificate, validatePayloadSignatureStatus} from '../scripts/signature-tools.mjs';

const fixture = await readFile(new URL('./fixtures/keys.pub', import.meta.url), 'utf8');
const canonical = fixture.trim().split(/\s+/).slice(0, 2).join(' ') + '\n';
const policy = {listId: 'production', sequence: 1, issuedAt: 100, expiresAt: 300};
const document = await makeSignedDocument(fixture, policy);
// Structural fixture only: this armor is NOT a cryptographic signature and must never be trusted as one.
const signature = '-----BEGIN PGP SIGNATURE-----\n\nYWJj\n-----END PGP SIGNATURE-----\n';

test('preparation strips all key comments BEFORE signing; document bytes and metadata are exact', async () => {
  assert.equal(document, '# conf-sshd-signed-v1\n# list-id production\n# sequence 1\n# issued-at 100\n# expires-at 300\n# revoke no\n# key-count 1\n# end-metadata\n' + canonical);
  const parsed = await parseSignedDocument(document, {now: 200, listId: 'production'});
  assert.equal(parsed.document, document);
  assert.equal(parsed.keys[0].label, 'Server key 1');
  assert.equal(parsed.metadata.documentSha256, createHash('sha256').update(document).digest('hex'));
});

test('bundle parsing returns exact document and signature without implying cryptographic verification', async () => {
  const bundle = document + SIGNATURE_SEPARATOR + signature;
  const parsed = await parseSignedBundle(bundle, {now: 200});
  assert.equal(parsed.bundle, bundle); assert.equal(parsed.document, document); assert.equal(parsed.signature, signature);
  assert.equal(parsed.verified, undefined);
  assert.equal(parsed.metadata.sequence, 1);
});

test('signed documents reject comments, CRLF, normalization, duplicate keys, padding changes and trailing bytes', async () => {
  for (const changed of [document.replace(canonical, fixture), document.replaceAll('\n','\r\n'), document.replace(canonical, canonical.replace(' ', '\t')), document.replace(canonical, canonical + canonical), document + '\n', document.slice(0, -1), document.replace(canonical, canonical + '# extra\n'), document.replace('key-count 1','key-count 2')]) await assert.rejects(parseSignedDocument(changed, {now:200}));
});

test('metadata is fixed-order, single-instance, canonical and bounded', async () => {
  for (const [from,to] of [['sequence 1','sequence 0'], ['sequence 1','sequence 01'], ['sequence 1','sequence 2147483648'], ['issued-at 100','issued-at 0100'], ['expires-at 300','expires-at 100'], ['expires-at 300','expires-at 10000000000'], ['list-id production','list-id has space'], ['revoke no','revoke yes'], ['key-count 1','key-count 1001'], ['# end-metadata','# unknown value\n# end-metadata']]) await assert.rejects(parseSignedDocument(document.replace(from,to), {now:200}));
  await assert.rejects(parseSignedDocument(document, {now:200,listId:'different'}));
  await assert.rejects(parseSignedDocument(document + 'x'.repeat(SIGNED_RELEASE_LIMITS.documentBytes), {now:200}));
});

test('freshness rejects expiration and future issue, optional transport parsing does not enforce client freshness', async () => {
  await assert.rejects(parseSignedDocument(document, {now:300}), /expired/);
  const future = await makeSignedDocument(fixture, {...policy,issuedAt:501,expiresAt:800});
  await assert.rejects(parseSignedDocument(future, {now:200}), /not yet/);
  assert.equal((await parseSignedDocument(future, {now:201})).metadata.issuedAt, 501);
  assert.equal((await parseSignedDocument(document, {now:999,checkFreshness:false})).metadata.sequence, 1);
});

test('empty revocation requires signed explicit revoke, no nonempty revoke accepted', async () => {
  const empty = await makeSignedDocument('', {...policy,revoke:true});
  assert.equal((await parseSignedDocument(empty, {now:200})).metadata.revoke, true);
  for (const args of [['',policy], [fixture,{...policy,revoke:true}]]) await assert.rejects(makeSignedDocument(...args));
});

test('malformed or missing signatures do not block OFF documents but fail strict shape policy', async () => {
  for (const invalid of [null, '', signature.replace('PGP SIGNATURE','PGP PRIVATE KEY BLOCK'), signature.slice(0,-1), signature + signature, 'x'.repeat(SIGNED_RELEASE_LIMITS.signatureBytes+1)]) {
    const off = await parsePublishedSignedRelease(document, invalid, {checkFreshness:false});
    assert.equal(off.document, document); assert.equal(off.signature,null); assert.equal(off.bundle,null);
    await assert.rejects(parsePublishedSignedRelease(document, invalid, {now:200,requireSigned:true}));
  }
  assert.equal(validateSignature(signature), signature);
  await assert.rejects(parseSignedBundle(document + SIGNATURE_SEPARATOR + signature + SIGNATURE_SEPARATOR, {now:200}));
});

test('preparation CLI never overwrites source/output and packs without altering signed bytes', async () => {
  const dir = await mkdtemp(join(tmpdir(),'conf-prep-'));
  try {
    const input=join(dir,'keys'), output=join(dir,'document'), sig=join(dir,'signature'), bundle=join(dir,'bundle');
    await writeFile(input, fixture); await writeFile(sig, signature);
    const args=['--input',input,'--output',output,'--list-id','production','--sequence','1','--issued-at','100','--expires-at','300'];
    await prepare(args); assert.equal(await readFile(output,'utf8'),document);
    await assert.rejects(prepare(args),/EEXIST/);
    await prepare(['--input',output,'--signature',sig,'--bundle',bundle]);
    assert.equal(await readFile(bundle,'utf8'),document+SIGNATURE_SEPARATOR+signature);
    await assert.rejects(prepare([...args,'--sequence','2']));
    await assert.rejects(prepare(args.map(value=>value==='100'?'0100':value)));
  } finally { await rm(dir,{recursive:true,force:true}); }
});

test('deployment client defaults are OFF and reject unsafe templates or incomplete ON pins', () => {
  assert.deepEqual(validateClientDefaults(),{gpgVerification:'off',fingerprint:'',pinMode:'primary',listId:'',email:''});
  assert.equal(validateClientDefaults({gpgVerification:'on',fingerprint:'a'.repeat(40),listId:'prod',email:'release@example.com'}).fingerprint,'A'.repeat(40));
  for (const value of [null,{gpgVerification:'yes'},{gpgVerification:'on'},{fingerprint:'short'},{listId:'bad space'},{listId:'-'},{pinMode:'any'},{email:"a'@example.com"},{email:'x@example.com\n'},{unknown:1}]) assert.throws(()=>validateClientDefaults(value));
  const base={baseUrl:'https://ssh.example.com',repositoryUrl:'https://github.com/example/repo',defaultCron:'*/15 * * * *',allowEmpty:false};
  assert.doesNotThrow(()=>validateConfig({...base,signedRelease:{listId:'prod',publicKeyFile:'keys/certificate.asc',fingerprint:'A'.repeat(40)}}));
  for (const signedRelease of [{listId:'prod',publicKeyFile:'../secret'}, {listId:'prod',fingerprint:'A'.repeat(40)}, {listId:'bad id'}, {listId:'prod',publicKeyFile:'keys/key.asc',fingerprint:'123'}]) assert.throws(()=>validateConfig({...base,signedRelease}));
});

test('public certificate envelope rejects private material and unbounded input', () => {
  for (const text of ['-----BEGIN PGP PRIVATE KEY BLOCK-----\nabc\n-----END PGP PRIVATE KEY BLOCK-----\n', 'x'.repeat(SIGNED_RELEASE_LIMITS.publicKeyBytes+1), '-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc\n-----END PGP PUBLIC KEY BLOCK-----\n-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n-----END PGP PUBLIC KEY BLOCK-----\n']) assert.throws(()=>validatePublicCertificate(text));
});

async function buildFixture(config, action) {
  const directory=await mkdtemp(join(tmpdir(),'conf-signed-build-'));
  try {
    await cp(join(root,'site'),join(directory,'site'),{recursive:true});await mkdir(join(directory,'keys'));
    await cp(join(root,'conf-sshd.sh'),join(directory,'conf-sshd.sh'));
    await writeFile(join(directory,'deployment.json'),JSON.stringify({baseUrl:'https://ssh.example.com',repositoryUrl:'https://github.com/example/repo',defaultCron:'*/15 * * * *',allowEmpty:false,...config}));
    return await action(directory,()=>build({directory,revision:'d'.repeat(40),publishedAt:'2026-10-13T00:00:00.000Z'}));
  } finally {await rm(directory,{recursive:true,force:true});}
}

test('Git build publishes exact detached files as Worker Static Assets and generated bytes', async () => {
  await buildFixture({},async (dir,buildNow)=>{
    await writeFile(join(dir,'keys/ssh.keys'),document);await writeFile(join(dir,'keys/ssh.keys.sig'),signature);
    await writeFile(join(dir,'keys/authorized_keys'),'# ordinary repository file deliberately empty\n');
    const result=await buildNow();assert.equal(result.keyCount,1);assert.equal(result.signedDocument,document);
    assert.equal(result.signature,signature);assert.equal(result.signatureAvailable,true);
    assert.equal(await readFile(join(dir,'cf-worker/public/ssh.keys'),'utf8'),document);
    assert.equal(await readFile(join(dir,'cf-worker/public/ssh.keys.sig'),'utf8'),signature);
    assert.equal(result.sha256,createHash('sha256').update(canonical).digest('hex'));
    const manifest=JSON.parse(await readFile(join(dir,'cf-worker/generated/manifest.json'),'utf8'));
    assert.equal(manifest.signedMetadata.sequence,1);assert.equal(manifest.signedDocument,undefined);
    assert.equal(manifest.signature,undefined);assert.equal(manifest.publicCertificate,undefined);
  });
});

test('Git missing/malformed signature is usable with OFF; bundle and detached files cannot conflict', async () => {
  await buildFixture({},async (dir,buildNow)=>{
    await writeFile(join(dir,'keys/ssh.keys'),document);
    for(const content of [null,'bad']){
      if(content!==null)await writeFile(join(dir,'keys/ssh.keys.sig'),content);
      const result=await buildNow();assert.equal(result.signedDocument,document);assert.equal(result.signature,null);
      await assert.rejects(readFile(join(dir,'cf-worker/public/ssh.keys.sig')),{code:'ENOENT'});
    }
    await writeFile(join(dir,'keys/release.bundle'),document+SIGNATURE_SEPARATOR+signature);
    await assert.rejects(buildNow(),/not both/);
  });
});

test('Git revocation bundle overrides legacy empty policy without falling back', async () => {
  await buildFixture({fallbackSources:['https://keys.example.com/fallback']},async (dir,buildNow)=>{
    const revoke=await makeSignedDocument('',{...policy,revoke:true});
    await writeFile(join(dir,'keys/release.bundle'),revoke+SIGNATURE_SEPARATOR+signature);
    const result=await buildNow();assert.equal(result.allowEmpty,true);assert.equal(result.keyCount,0);assert.equal(result.needsFallback,false);
    assert.equal(await readFile(join(dir,'cf-worker/public/ssh.keys'),'utf8'),revoke);
  });
});

test('dynamic Gist builds need no local keys and must not publish stale static key placeholders', async () => {
  await buildFixture({keySource:{type:'gist',id:'a'.repeat(32),ownerId:7,ownerLogin:'example'}},async (dir,buildNow)=>{
    await writeFile(join(dir,'keys/authorized_keys'),fixture);
    const result=await buildNow();assert.equal(result.keys.length,0);assert.equal(result.needsSource,true);assert.equal(result.sha256,null);
    await assert.rejects(readFile(join(dir,'cf-worker/public/ssh.keys')),{code:'ENOENT'});
    assert.doesNotMatch(await readFile(join(dir,'cf-worker/generated/release.js'),'utf8'),/TEST-ONLY/);
  });
});

test('ON static defaults fail known-missing signatures and mismatched list IDs', async () => {
  await buildFixture({clientDefaults:{gpgVerification:'on',fingerprint:'A'.repeat(40),listId:'production'}},async (dir,buildNow)=>{
    await writeFile(join(dir,'keys/authorized_keys'),fixture);
    await assert.rejects(buildNow(),/require a signed document/);
    await writeFile(join(dir,'keys/ssh.keys'),document);await writeFile(join(dir,'keys/ssh.keys.sig'),signature);
    assert.equal((await buildNow()).clientDefaults.gpgVerification,'on');
    await writeFile(join(dir,'keys/ssh.keys'),document.replace('list-id production','list-id wrong'));
    await assert.rejects(buildNow(),/list ID differs/);
  });
});

test('real detached signatures verify with a public-only isolated GPG keyring and reject tampering/pin mismatch', async () => {
  const fixture = openPgpFixture({subkey:true});
  const actualSignature=fixture.sign(document), bundle=document+SIGNATURE_SEPARATOR+actualSignature;
  assert.equal(await checkSigningCertificate(fixture.publicKey,fixture.primaryFingerprint,bundle),fixture.primaryFingerprint);
  await assert.rejects(checkSigningCertificate(fixture.publicKey,'A'.repeat(40),bundle),/fingerprint mismatch/);
  await assert.rejects(checkSigningCertificate(fixture.publicKey,fixture.primaryFingerprint,document.replace('sequence 1','sequence 2')+SIGNATURE_SEPARATOR+actualSignature),/verification failed/);
  await assert.rejects(checkSigningCertificate(fixture.publicKey,fixture.primaryFingerprint,document+SIGNATURE_SEPARATOR+signature),/verification failed/);
});

test('real revoked and expired signing identities fail even for formerly valid payload signatures', async () => {
  for(const options of [{expired:true},{revoked:true}]) {
    const fixture=openPgpFixture(options);
    await assert.rejects(checkSigningCertificate(fixture.publicKey,fixture.primaryFingerprint,document+SIGNATURE_SEPARATOR+fixture.sign(document)));
  }
});

test('strict GPG status requires binary v4 strong hash and rejects every failure marker', () => {
  const fp='A'.repeat(40), status=`[GNUPG:] VALIDSIG ${fp} 2026-01-01 100 0 4 0 1 8 00 ${fp}\n`;
  assert.equal(validatePayloadSignatureStatus(status,fp).primaryFingerprint,fp);
  for(const token of ['BADSIG','ERRSIG','NO_PUBKEY','EXPSIG','EXPKEYSIG','REVKEYSIG','KEYEXPIRED','SIGEXPIRED','KEYREVOKED','FAILURE','ERROR','NODATA','BADARMOR']) assert.throws(()=>validatePayloadSignatureStatus(status+`[GNUPG:] ${token} value\n`,fp));
  for(const invalid of [status+status,status.replace('1 8 00','1 11 00'),status.replace('1 8 00','1 2 00'),status.replace('1 8 00','1 8 01'),status.replace('0 4 0','0 5 0'),status.trim().split(' ').slice(0,-1).join(' '),status.replace('100 0 4','100 101 4')]) assert.throws(()=>validatePayloadSignatureStatus(invalid,fp));
});

test('build publishes only a validated public certificate and verifies exact signed bytes against its primary pin', async () => {
  const fixture=openPgpFixture({subkey:true});
  await buildFixture({signedRelease:{listId:'production',publicKeyFile:'keys/certificate.asc',fingerprint:fixture.primaryFingerprint}},async (dir,buildNow)=>{
    await writeFile(join(dir,'keys/certificate.asc'),fixture.publicKey);
    await writeFile(join(dir,'keys/ssh.keys'),document);await writeFile(join(dir,'keys/ssh.keys.sig'),fixture.sign(document));
    const release=await buildNow();assert.equal(release.publicCertificate,fixture.publicKey);
    assert.equal(await readFile(join(dir,'cf-worker/public/public-key.gpg'),'utf8'),fixture.publicKey);
    await writeFile(join(dir,'keys/ssh.keys'),document.replace('sequence 1','sequence 2'));
    await assert.rejects(buildNow(),/verification failed/);
  });
});

test('remote verification ON cannot pass a dynamic Gist with a missing detached signature', async () => {
  const revision='a'.repeat(40), gist={type:'gist',id:'b'.repeat(32),ownerId:1,ownerLogin:'user'}, sha256=createHash('sha256').update(canonical).digest('hex');
  const manifest={revision,baseUrl:'https://ssh.example.com',keySource:gist,needsSource:true,fallbackSources:[],clientDefaults:{gpgVerification:'on'}};
  const fetcher=async url=>new Response(url.endsWith('/release.json')?JSON.stringify({revision,sha256,keyCount:1,source:{...gist,gistRevision:'c'.repeat(40)}}):url.endsWith('/ssh.keys')?document:'',{status:url.endsWith('/ssh.keys.sig')?404:200});
  await assert.rejects(verifyRemote(manifest,fetcher),/signature is missing/);
  const text=await verifyRemote({...manifest,clientDefaults:{gpgVerification:'off'}},fetcher);
  assert.match(text,/OpenPGP not checked/);
});


test('cryptographically valid text-mode signatures are rejected by exact-byte payload policy',async()=>{
  const fixture=openPgpFixture();
  const textSignature=fixture.signText(document);
  const dir=await mkdtemp(join(tmpdir(),'conf-text-signature-'));
  try {
    const cert=join(dir,'public.asc'),ring=join(dir,'public.gpg'),doc=join(dir,'document'),sig=join(dir,'document.sig');
    await writeFile(cert,fixture.publicKey,{mode:0o600});
    await writeFile(doc,document,{mode:0o600});
    await writeFile(sig,textSignature,{mode:0o600});
    const args=['--no-options','--homedir',dir,'--batch','--no-tty','--no-autostart','--no-auto-key-retrieve','--auto-key-locate','clear'];
    execFileSync('gpg',[...args,'--output',ring,'--dearmor',cert],{stdio:'pipe'});
    const status=execFileSync('gpg',[...args,'--no-default-keyring','--keyring',ring,'--status-fd','1','--verify',sig,doc],{encoding:'utf8',stdio:['ignore','pipe','pipe']});
    assert.match(status,/\[GNUPG:\] VALIDSIG .* 01 /);
    await assert.rejects(checkSigningCertificate(fixture.publicKey,fixture.primaryFingerprint,document+SIGNATURE_SEPARATOR+textSignature),/binary/);
  } finally {await rm(dir,{recursive:true,force:true});}
});


test('list identity dash is reserved consistently with local enrollment state',async()=>{
  await assert.rejects(makeSignedDocument(fixture,{...policy,listId:'-'}),/list ID/);
  await assert.rejects(parseSignedDocument(document.replace('# list-id production','# list-id -'),{checkFreshness:false}),/list ID/);
  assert.throws(()=>validateConfig({baseUrl:'https://ssh.example.com',repositoryUrl:'https://github.com/test/repo',defaultCron:'*/15 * * * *',allowEmpty:false,signedRelease:{listId:'-'}}),/list ID/);
});
