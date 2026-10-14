import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {verifyProduction, verifyRemote} from '../scripts/verify-release.mjs';
import {makeKeyBundle} from '../cf-worker/src/key-source.js';
import {makeSignedDocument, SIGNATURE_SEPARATOR} from '../cf-worker/src/signed-release.js';
import {openPgpFixture} from './helpers/openpgp-fixture.mjs';

const fixture = await readFile(new URL('./fixtures/keys.pub', import.meta.url), 'utf8');
const revision = 'a'.repeat(40), gistRevision = 'b'.repeat(40);
const source = {type:'gist',id:'c'.repeat(32),ownerId:7,ownerLogin:'example',file:'ssh.keys',signatureFile:'ssh.keys.sig',bundleFile:'release.bundle'};
const fallback = 'https://keys.example.com/fallback';
const release = {revision,testFixture:false,keys:[],allowEmpty:false,needsSource:true,keySource:source,fallbackSources:[fallback],baseUrl:'https://ssh.example.com',clientDefaults:{gpgVerification:'off'}};
const policy = {listId:'production',sequence:1,issuedAt:100,expiresAt:300};
// Armor-shape fixture only. Crypto tests below generate and verify a real detached signature.
const signature = '-----BEGIN PGP SIGNATURE-----\n\nYWJj\n-----END PGP SIGNATURE-----\n';
const strict = {...release,clientDefaults:{gpgVerification:'on',listId:'production',fingerprint:'A'.repeat(40),pinMode:'primary'}};
const gistFile = (name,content) => ({filename:name,content,size:Buffer.byteLength(content),truncated:false});
function gistFetcher(content, {files, mutate = data => data} = {}) {
  const visited = [];
  const fetcher = async (url, init) => {
    visited.push(url);
    assert.notEqual(url,fallback,'Deployment preflight must never use fallback to mask the primary');
    assert.equal(init.redirect,'manual');assert.equal(init.cache,'no-store');
    assert.ok(init.signal instanceof AbortSignal);
    assert.ok([`https://api.github.com/gists/${source.id}`,`https://api.github.com/gists/${source.id}/${gistRevision}`].includes(url));
    const data = {id:source.id,owner:{id:source.ownerId},public:true,truncated:false,history:[{version:gistRevision}],files:files ?? {'ssh.keys':gistFile('ssh.keys',content)}};
    return new Response(JSON.stringify(mutate(data)));
  };
  return {fetcher,visited};
}

test('preflight rejects fixture/legacy unconfigured Git builds before any network request',async()=>{
  const noFetch=()=>assert.fail('Unconfigured builds must not make network requests');
  await assert.rejects(verifyProduction({...release,testFixture:true},noFetch),/test-fixture/);
  await assert.rejects(verifyProduction({...release,keySource:{type:'git'},allowEmpty:true},noFetch),/no configured primary file/);
  await assert.rejects(verifyProduction({...release,keySource:{type:'git'},primaryFile:'keys/authorized_keys',allowEmpty:true},noFetch),/explicitly empty primary/);
});

test('Gist preflight pins both reads and accepts valid keys or an existing blank OFF file',async()=>{
  for(const content of [fixture,'',' ','\n',' \t\r\n']) {
    const {fetcher,visited}=gistFetcher(content);
    assert.match(await verifyProduction(release,fetcher),new RegExp(`${content===fixture?1:0} key\\(s\\) from gist`));
    assert.deepEqual(visited,[`https://api.github.com/gists/${source.id}`,`https://api.github.com/gists/${source.id}/${gistRevision}`]);
  }
});

test('Gist preflight fails absent, comments-only, invalid and wrong-owner primary despite a configured fallback',async()=>{
  for(const options of [
    {files:{}},
    {files:{'ssh.keys':gistFile('ssh.keys','# Add keys here.\n')}},
    {files:{'ssh.keys':gistFile('ssh.keys','ssh-ed25519 not-a-key')}},
    {mutate:data=>({...data,owner:{id:8}})},
    {mutate:data=>({...data,history:[]})},
    {mutate:data=>({...data,public:false})},
  ]) {
    const {fetcher}=gistFetcher(fixture,options);
    await assert.rejects(verifyProduction({...release,allowEmpty:true},fetcher),/source|primary/i);
  }
});

test('Gist preflight cannot hide a primary HTTP/network failure or timeout behind fallback keys',async()=>{
  for(const failure of ['404','503','network','timeout']) {
    const visited=[];
    const fetcher=async url=>{
      visited.push(url);assert.notEqual(url,fallback);
      if(failure==='network') throw Error('network failure');
      if(failure==='timeout') return new Promise(()=>{});
      return new Response('',{status:Number(failure)});
    };
    await assert.rejects(verifyProduction(release,fetcher,{timeoutMs:5}),/source|primary/i);
    assert.ok(visited.length>0);
  }
});

test('Gist ON preflight requires a current signed release and explicit signed revoke',async()=>{
  for(const content of ['', ' \t\n',fixture]) await assert.rejects(verifyProduction(strict,gistFetcher(content).fetcher,{now:200}),/source|primary/i);
  const revoke=await makeSignedDocument('',{...policy,revoke:true});
  const populated=await makeSignedDocument(fixture,policy);
  for(const document of [revoke,populated]) {
    const files={'ssh.keys':gistFile('ssh.keys',document),'ssh.keys.sig':gistFile('ssh.keys.sig',signature)};
    const result=await verifyProduction(strict,gistFetcher(null,{files}).fetcher,{now:200});
    assert.match(result,new RegExp(`${document===revoke?0:1} key\\(s\\) from gist`));
    assert.match(result,/OpenPGP not checked/);
    await assert.rejects(verifyProduction(strict,gistFetcher(null,{files}).fetcher,{now:300}),/source|primary/i);
    await assert.rejects(verifyProduction(strict,gistFetcher(document).fetcher,{now:200}),/source|primary/i);
    files['ssh.keys.sig']=gistFile('ssh.keys.sig','bad signature');
    await assert.rejects(verifyProduction(strict,gistFetcher(null,{files}).fetcher,{now:200}),/source|primary/i);
  }
  const wrong=await makeSignedDocument('',{...policy,listId:'wrong',revoke:true});
  const files={'release.bundle':gistFile('release.bundle',wrong+SIGNATURE_SEPARATOR+signature)};
  await assert.rejects(verifyProduction(strict,gistFetcher(null,{files}).fetcher,{now:200}),/list ID differs/);
});

test('configured Gist public certificate verifies the exact signed revoke before deployment',async()=>{
  const signer=openPgpFixture();
    const now=Math.floor(Date.now()/1000);
    const document=await makeSignedDocument('',{...policy,revoke:true,issuedAt:now-10,expiresAt:now+600});
    const releaseWithCertificate={...strict,publicCertificate:signer.publicKey,signedRelease:{listId:'production',publicKeyFile:'keys/certificate.asc',fingerprint:signer.primaryFingerprint},clientDefaults:{...strict.clientDefaults,fingerprint:signer.primaryFingerprint}};
    const files={'release.bundle':gistFile('release.bundle',document+SIGNATURE_SEPARATOR+signer.sign(document))};
    assert.doesNotMatch(await verifyProduction(releaseWithCertificate,gistFetcher(null,{files}).fetcher),/OpenPGP not checked/);
    files['release.bundle']=gistFile('release.bundle',document.replace('sequence 1','sequence 2')+SIGNATURE_SEPARATOR+signer.sign(document));
    await assert.rejects(verifyProduction(releaseWithCertificate,gistFetcher(null,{files}).fetcher),/signature verification failed/);
});

test('remote verification accepts an explicit empty pinned Gist with OFF but preserves ON rejection',async()=>{
  const empty=await makeKeyBundle([],revision,true);
  const metadata={revision,sha256:empty.sha256,keyCount:0,allowEmpty:true,source:{...source,gistRevision}};
  const fetcher=async url=>new Response(url.endsWith('/release.json')?JSON.stringify(metadata):empty.text);
  assert.match(await verifyRemote(release,fetcher),/\(0 keys\)/);
  await assert.rejects(verifyRemote(strict,fetcher),/signed-format/);
  metadata.allowEmpty=false;
  await assert.rejects(verifyRemote(release,fetcher),/empty\/canonical/);
  metadata.allowEmpty=true;metadata.source={type:'fallback',url:fallback};
  await assert.rejects(verifyRemote(release,fetcher),/empty\/canonical/);
});

test('remote verification ON checks signed-revoke freshness without claiming crypto when no certificate exists',async()=>{
  const document=await makeSignedDocument('',{...policy,revoke:true});
  const empty=await makeKeyBundle([],revision,true);
  const metadata={revision,sha256:empty.sha256,keyCount:0,allowEmpty:true,source:{...source,gistRevision}};
  const fetcher=async url=>new Response(url.endsWith('/release.json')?JSON.stringify(metadata):url.endsWith('/ssh.keys.sig')?signature:document);
  assert.match(await verifyRemote(strict,fetcher,{now:200}),/OpenPGP not checked/);
  await assert.rejects(verifyRemote(strict,fetcher,{now:300}),/expired/);
});
