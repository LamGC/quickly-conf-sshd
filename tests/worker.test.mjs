import test from 'node:test';
import assert from 'node:assert/strict';
import {createHandler} from '../cf-worker/src/router.js';
import {parsePublicKeys,makeKeyBundle} from '../cf-worker/src/key-source.js';
import {readFile} from 'node:fs/promises';
const fixture=await readFile(new URL('./fixtures/keys.pub',import.meta.url),'utf8');
const keys=await parsePublicKeys(fixture);
const revision='a'.repeat(40);
const bundle=await makeKeyBundle(keys,revision,false);
const release={revision,publishedAt:'2026-10-12',keyCount:1,allowEmpty:false,sha256:bundle.sha256,script:'#!/bin/sh\n',keysText:bundle.text,keys,fallbackSources:[],repositoryUrl:'https://github.com/test/repo',commands:[],pageTemplate:await readFile(new URL('../site/index.html',import.meta.url),'utf8')};
const fetch=createHandler(release);
const requests=[];
const env={ASSETS:{fetch:async request=>{requests.push(new URL(request.url).pathname);return new Response('asset:'+new URL(request.url).pathname,{headers:{'Content-Type':request.url.endsWith('.css')?'text/css':'text/html'}})}}};
const request=(path,init={})=>new Request('https://ssh.example.com'+path,init);
test('explicit endpoints ignore user agent and are never cached',async()=>{
  for(const [path,body] of [['/script.sh',release.script],['/ssh.keys',release.keysText]]) {
    const response=await fetch(request(path,{headers:{Accept:'text/html'}}),env);
    assert.equal(await response.text(),body);assert.equal(response.headers.get('Cache-Control'),'no-store');assert.match(response.headers.get('Content-Type'),/^text\/plain/);
  }
});
test('root serves browser HTML and legacy curl script without content mixing',async()=>{
  for(const agent of ['curl/8.1.0','libcurl/8.1.0','Wget/1.21.3','HTTPie/3.2.4']){
    const response=await fetch(request('/',{headers:{'User-Agent':agent,Accept:'*/*'}}),env);
    assert.equal(await response.text(),release.script);assert.equal(response.headers.get('Vary'),'Accept, User-Agent');
  }
  const explicit=await fetch(request('/',{headers:{'User-Agent':'curl/8','Accept':'text/html'}}),env);
  assert.match(await explicit.text(),/<html lang="zh-CN">/);
  assert.match((await fetch(request('/'),env)).headers.get('Content-Type'),/^text\/html/);
});
test('metadata is current release; invalid methods and paths fail rather than returning HTML',async()=>{
  const metadata=await (await fetch(request('/release.json'),env)).json();assert.equal(metadata.revision,release.revision);assert.equal(metadata.keyCount,1);
  for(const path of ['/script.s','/ssh.key','/index.html','/assets/../../script.sh','/api/keys']) {
    if(path==='/assets/../../script.sh') continue; // URL canonicalization is intentionally standard.
    const response=await fetch(request(path),env);assert.equal(response.status,404);assert.match(response.headers.get('Content-Type'),/^text\/plain/);
  }
  const post=await fetch(request('/ssh.keys',{method:'POST'}),env);assert.equal(post.status,405);assert.equal(post.headers.get('Allow'),'GET, HEAD');
});
test('HEAD returns headers without body and missing page fails with 503',async()=>{
  for(const path of ['/','/script.sh','/ssh.keys','/release.json']) assert.equal(await (await fetch(request(path,{method:'HEAD'}),env)).text(),'');
  assert.equal((await createHandler({...release,pageTemplate:null})(request('/'),env)).status,503);
});
test('fingerprinted assets cached while security headers retained',async()=>{
  const response=await fetch(request('/assets/app.012345abcdef.js'),env);assert.match(response.headers.get('Cache-Control'),/immutable/);assert.equal(response.headers.get('X-Content-Type-Options'),'nosniff');
  const missing=await fetch(request('/assets/missing.js'),{ASSETS:{fetch:async()=>new Response('missing',{status:404})}});assert.equal(missing.status,404);
});

test('fallback page and key metadata represent one effective snapshot; unavailable does not revoke',async()=>{
  const fallback={...release,keys:[],keyCount:0,sha256:null,keysText:null,fallbackSources:['https://keys.example.com/server.keys']};
  const handler=createHandler(fallback,{fetchImpl:async()=>new Response(fixture)});
  const html=await (await handler(request('/'),env)).text();
  assert.ok(html.includes('备用源可用'));assert.ok(html.includes('https://keys.example.com/server.keys'));assert.ok(!html.includes(keys[0].fingerprint));assert.ok(!html.includes(keys[0].text));
  const match=html.match(/<script id="release-data" type="application\/json">([\s\S]*?)<\/script>/);
  const embedded=JSON.parse(match[1]);assert.equal(embedded.sha256,bundle.sha256);assert.equal(embedded.keyCount,1);assert.equal(embedded.keys,undefined);
  const metadata=await (await handler(request('/release.json'),env)).json();assert.equal(metadata.keyRevision,bundle.sha256);assert.equal(metadata.source.type,'fallback');
  assert.equal(await (await handler(request('/ssh.keys'),env)).text(),bundle.text);
  const unavailable=createHandler(fallback,{fetchImpl:async()=>new Response('',{status:503})});
  for(const path of ['/ssh.keys','/release.json','/'])assert.equal((await unavailable(request(path),env)).status,503);
  const failureHTML=await (await unavailable(request('/'),env)).text();assert.ok(failureHTML.includes('未发布撤销指令'));assert.ok(!failureHTML.includes('此版本明确撤销全部受管理公钥'));
  assert.equal((await unavailable(request('/script.sh'),env)).status,200);
  assert.equal(await (await unavailable(request('/',{headers:{'User-Agent':'curl/8'}}),env)).text(),release.script);
});
test('explicit empty revocation suppresses fallback in page, metadata and keys',async()=>{
  const handler=createHandler({...release,keys:[],keyCount:0,allowEmpty:true,fallbackSources:['https://keys.example.com/server.keys']},{fetchImpl:async()=>{throw Error('must not fetch')}});
  const html=await (await handler(request('/'),env)).text();assert.ok(html.includes('明确撤销'));assert.ok(!html.includes('未发布撤销指令'));
  const keysText=await (await handler(request('/ssh.keys'),env)).text();assert.match(keysText,/# key-count 0\n# allow-empty yes/);
});

test('signature endpoint never invents a signature for unsigned sources',async()=>{
  for(const method of ['GET','HEAD']) {
    const response=await fetch(request('/ssh.keys.sig',{method}),env);
    assert.equal(response.status,404);
    assert.equal(response.headers.get('Cache-Control'),'no-store');
    if(method==='HEAD') assert.equal(await response.text(),'');
  }
  const metadata=await(await fetch(request('/release.json'),env)).json();
  assert.equal(metadata.signatureAvailable,false);
  assert.equal(metadata.signatureVerifiedByWorker,false);
  assert.equal(metadata.signedMetadata,null);
});

test('public certificate is independent of unavailable key sources and never cached',async()=>{
  assert.equal((await fetch(request('/public-key.gpg'),env)).status,404);
  const certificate='-----BEGIN PGP PUBLIC KEY BLOCK-----\nfixture-public-only\n-----END PGP PUBLIC KEY BLOCK-----\n';
  const handler=createHandler({...release,publicCertificate:certificate,keys:[],allowEmpty:false,fallbackSources:['https://bad.example.com/keys']},{fetchImpl:async()=>{throw Error('certificate must not resolve keys')}});
  const response=await handler(request('/public-key.gpg'),env);
  assert.equal(response.status,200);assert.equal(await response.text(),certificate);
  assert.equal(response.headers.get('Cache-Control'),'no-store');
  assert.equal(response.headers.get('Content-Type'),'application/pgp-keys');
  assert.equal(await(await handler(request('/public-key.gpg',{method:'HEAD'}),env)).text(),'');
});

test('signature endpoint pairs with exact signed document, never the legacy wrapper',async()=>{
  const {makeSignedDocument}=await import('../cf-worker/src/signed-release.js');
  const document=await makeSignedDocument(fixture,{listId:'test-list',sequence:1,issuedAt:1700000000,expiresAt:1900000000});
  // Structurally valid, deliberately non-cryptographic armor tests routing only.
  const signature='-----BEGIN PGP SIGNATURE-----\n\nYWJj\n-----END PGP SIGNATURE-----\n';
  const handler=createHandler({...release,signedDocument:document,signature});
  const keysResponse=await handler(request('/ssh.keys'),env);
  assert.equal(keysResponse.status,200);assert.equal(await keysResponse.text(),document);
  const sigResponse=await handler(request('/ssh.keys.sig'),env);
  assert.equal(sigResponse.status,200);assert.equal(await sigResponse.text(),signature);
  assert.equal(sigResponse.headers.get('Content-Type'),'application/pgp-signature');
  assert.equal(sigResponse.headers.get('Cache-Control'),'no-store');
  const metadata=await(await handler(request('/release.json'),env)).json();
  assert.equal(metadata.signatureAvailable,true);assert.equal(metadata.signatureVerifiedByWorker,false);
  assert.equal(metadata.signedMetadata.sequence,1);
  assert.equal(metadata.keyRevision,metadata.signedMetadata.documentSha256);
  const unsigned=createHandler({...release,signedDocument:document,signature:null});
  assert.equal(await(await unsigned(request('/ssh.keys'),env)).text(),document);
  assert.equal((await unsigned(request('/ssh.keys.sig'),env)).status,404);
});
