import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash, generateKeyPairSync} from 'node:crypto';
import {FallbackUnavailableError, KEY_SOURCE_LIMITS, isExplicitEmptyKeyFile, makeKeyBundle, parsePublicKeys, resolveKeys, validateFallbackSources} from '../cf-worker/src/key-source.js';
import {SIGNED_BUNDLE_MAX_BYTES, makeSignedDocument, SIGNATURE_SEPARATOR} from '../cf-worker/src/signed-release.js';

const fixture = await readFile(new URL('./fixtures/keys.pub', import.meta.url), 'utf8');
const canonical = fixture.trim().split(/\s+/).slice(0, 2).join(' ') + '\n';
const revision = 'a'.repeat(40);
const urls = ['https://keys.example.org/first.keys', 'https://keys.example.org/second.keys', 'https://keys.example.org/third.keys'];
const emptyRelease = {keys: [], allowEmpty: false, revision, fallbackSources: urls};
const fixtureKeys = await parsePublicKeys(fixture);
const hash = text => createHash('sha256').update(text).digest('hex');
const string = value => {
  const bytes = typeof value === 'string' ? Buffer.from(value) : Buffer.from(value);
  const prefix = Buffer.alloc(4); prefix.writeUInt32BE(bytes.length);
  return Buffer.concat([prefix, bytes]);
};
const wire = (...fields) => Buffer.concat(fields.map(string));
const keyLine = (type, bytes, comment = '') => `${type} ${bytes.toString('base64')}${comment ? ` ${comment}` : ''}\n`;
const secondFixture = keyLine('ssh-ed25519', wire('ssh-ed25519', Buffer.from('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', 'hex')), 'second');
const keyData = Buffer.from(fixture.split(/\s+/)[1], 'base64');
const response = text => new Response(text, {headers: {'Content-Type': 'text/plain; charset=utf-8'}});
async function unavailable(fetcher, options = {}, release = emptyRelease) {
  let caught;
  try { await resolveKeys(release, fetcher, options); } catch (error) { caught = error; }
  assert.ok(caught instanceof FallbackUnavailableError);
  assert.equal(caught.code, 'KEY_SOURCES_UNAVAILABLE');
  return caught;
}

test('repository keys win without any upstream request and have complete protocol metadata', async () => {
  const result = await resolveKeys({...emptyRelease, keys: fixtureKeys}, () => assert.fail('Repository keys must not fetch'));
  assert.deepEqual(result.source, {type: 'repository'});
  assert.equal(result.revision, revision);
  assert.equal(result.keyCount, 1);
  assert.equal(result.sha256, hash(canonical));
  assert.equal(result.keyRevision, result.sha256);
  assert.equal(result.keysText, `# conf-sshd-v1\n# revision ${revision}\n# key-count 1\n# allow-empty no\n# sha256 ${hash(canonical)}\n# end-metadata\n${canonical}`);
  assert.ok(Number.isFinite(Date.parse(result.fetchedAt)));
});

test('explicit empty revocation suppresses fallback; repository still wins when nonempty', async () => {
  const result = await resolveKeys({...emptyRelease, allowEmpty: true}, () => assert.fail('Revocation must not fetch'));
  assert.deepEqual(result.source, {type: 'explicit-empty'});
  assert.equal(result.keyCount, 0);
  assert.equal(result.sha256, hash(''));
  assert.match(result.keysText, /# allow-empty yes\n/);
  const populated = await resolveKeys({...emptyRelease, keys: fixtureKeys, allowEmpty: true}, () => assert.fail('Must not fetch'));
  assert.equal(populated.source.type, 'repository');
  assert.equal(populated.keyCount, 1);
});

test('first valid nonempty source wins in order, without aggregation or redirect/cache reuse', async () => {
  const visited = [];
  const result = await resolveKeys(emptyRelease, async (url, init) => {
    visited.push(url);
    assert.equal(init.cache, 'no-store'); assert.equal(init.redirect, 'manual'); assert.equal(init.method, 'GET');
    assert.match(init.headers['Cache-Control'], /no-store/); assert.ok(init.signal instanceof AbortSignal);
    return response(fixture);
  });
  assert.deepEqual(visited, [urls[0]]);
  assert.deepEqual(result.source, {type: 'fallback', url: urls[0]});
  assert.equal(result.keyCount, 1);
  assert.equal(result.sha256, hash(canonical));
});

test('malformed and empty sources are skipped before the next valid source', async () => {
  const visited = [];
  const result = await resolveKeys(emptyRelease, async url => {
    visited.push(url);
    return response([ '<html>upstream problem</html>', '# no keys\n\n', fixture ][urls.indexOf(url)]);
  });
  assert.deepEqual(visited, urls);
  assert.equal(result.source.url, urls[2]);
});

for (const status of [301, 302, 307, 308, 400, 404, 429, 500, 503]) {
  test(`HTTP ${status} is skipped without following redirects`, async () => {
    const visited = [];
    const result = await resolveKeys(emptyRelease, async url => {
      visited.push(url);
      return url === urls[0] ? new Response('Do not return this body: SECRET', {status, headers: {Location: 'https://unconfigured.example/keys'}}) : response(fixture);
    });
    assert.deepEqual(visited, urls.slice(0, 2));
    assert.equal(result.source.url, urls[1]);
  });
}

test('a response reported as redirected is rejected even when status is 200', async () => {
  const redirected = response(fixture);
  Object.defineProperty(redirected, 'redirected', {value: true});
  const result = await resolveKeys(emptyRelease, async url => url === urls[0] ? redirected : response(secondFixture));
  assert.equal(result.source.url, urls[1]);
  assert.equal(result.sha256, hash(secondFixture.trim().split(/\s+/).slice(0, 2).join(' ') + '\n'));
});

test('fetch timeout is bounded even when an upstream ignores AbortSignal', async () => {
  const visited = [];
  const result = await resolveKeys(emptyRelease, async url => {
    visited.push(url);
    if (url === urls[0]) return new Promise(() => {});
    return response(fixture);
  }, {timeoutMs: 20});
  assert.deepEqual(visited, urls.slice(0, 2));
  assert.equal(result.source.url, urls[1]);
});

test('timeout includes streamed body and cancels it before falling back', async () => {
  let cancelled = false;
  const body = new ReadableStream({start(controller) {controller.enqueue(new TextEncoder().encode(fixture));}, cancel() {cancelled = true;}});
  const result = await resolveKeys(emptyRelease, async url => url === urls[0] ? new Response(body) : response(secondFixture), {timeoutMs: 20});
  assert.equal(cancelled, true);
  assert.equal(result.source.url, urls[1]);
});

test('all failed sources return typed, bounded diagnostics without secret bodies or errors', async () => {
  const error = await unavailable(async url => {
    if (url === urls[0]) throw new Error('Credential SECRET network detail');
    if (url === urls[1]) return new Response('SECRET body', {status: 503});
    return response('# no keys\n');
  });
  assert.deepEqual(error.diagnostics, [{index: 0, code: 'network-error'}, {index: 1, code: 'http-error', status: 503}, {index: 2, code: 'empty'}]);
  assert.doesNotMatch(JSON.stringify(error), /SECRET|https:/);
});

test('no repository keys and no configured sources is unavailable without fetching', async () => {
  const error = await unavailable(() => assert.fail('No implicit GitHub or other source'), {}, {...emptyRelease, fallbackSources: []});
  assert.deepEqual(error.diagnostics, []);
});

test('streamed size is enforced even without or with a misleading Content-Length', async () => {
  for (const headers of [{}, {'Content-Length': '1'}]) {
    let cancelled = false;
    const body = new ReadableStream({start(controller) {controller.enqueue(new Uint8Array(70)); controller.enqueue(new Uint8Array(70));}, cancel() {cancelled = true;}});
    const error = await unavailable(async () => new Response(body, {headers}), {maxBytes: 128}, {...emptyRelease, fallbackSources: [urls[0]]});
    assert.equal(error.diagnostics[0].code, 'too-large');
    assert.equal(cancelled, true);
  }
});

test('oversized declared length is rejected without reading the body', async () => {
  const error = await unavailable(async () => new Response(fixture, {headers: {'Content-Length': String(SIGNED_BUNDLE_MAX_BYTES + 1)}}), {}, {...emptyRelease, fallbackSources: [urls[0]]});
  assert.equal(error.diagnostics[0].code, 'too-large');
});

test('invalid UTF-8 is rejected instead of silently replaced', async () => {
  const error = await unavailable(async () => new Response(Uint8Array.from([0xc3, 0x28])), {}, {...emptyRelease, fallbackSources: [urls[0]]});
  assert.equal(error.diagnostics[0].code, 'invalid-utf8');
});

test('changing upstream changes content revision while build revision stays fixed; no stale fallback', async () => {
  let body = fixture;
  const fetcher = async () => response(body);
  const release = {...emptyRelease, fallbackSources: [urls[0]]};
  const first = await resolveKeys(release, fetcher);
  body = secondFixture;
  const second = await resolveKeys(release, fetcher);
  assert.notEqual(first.keyRevision, second.keyRevision);
  assert.equal(first.revision, second.revision);
  body = '';
  await assert.rejects(resolveKeys(release, fetcher), FallbackUnavailableError);
});

test('octet-stream responses are accepted only after strict key parsing', async () => {
  const result = await resolveKeys(emptyRelease, async () => new Response(fixture, {headers: {'Content-Type': 'application/octet-stream'}}));
  assert.equal(result.keyCount, 1);
});

test('sources are trusted HTTPS config only, bounded, without credentials or fragments', () => {
  assert.deepEqual(validateFallbackSources(urls), urls);
  assert.deepEqual(validateFallbackSources(), []);
  for (const invalid of [null, {}, new Array(6).fill(urls[0]), ['http://example.org/key'], ['https://user:password@example.org/key'], ['https://example.org/key#fragment'], ['https://example.org/key#'], ['https://example.org/key\n'], ['data:text/plain,key'], ['//example.org/key']]) assert.throws(() => validateFallbackSources(invalid));
});

test('Unicode comments and CRLF are canonicalized, with a known SHA256 fingerprint', async () => {
  const input = fixture.trim().split(/\s+/).slice(0, 2).join('\t') + '\t 家用服务器  🔐\t张三\r\n';
  const [key] = await parsePublicKeys(input);
  assert.equal(key.label, '家用服务器 🔐 张三');
  assert.equal(key.fingerprint, 'SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8');
  assert.equal(key.text, `${fixture.trim().split(/\s+/).slice(0, 2).join(' ')} 家用服务器 🔐 张三`);
  const bundle = await makeKeyBundle([key], revision, false);
  assert.equal(bundle.sha256, hash(canonical));
});

test('duplicates, options, certificates, private keys, invalid controls, and junk are rejected', async () => {
  const cert = fixture.replaceAll('ssh-ed25519', 'ssh-ed25519-cert-v01@openssh.com');
  for (const invalid of [fixture + fixture, `restrict ${fixture}`, `command="id" ${fixture}`, cert, '-----BEGIN OPENSSH PRIVATE KEY-----\n', fixture + '<html>oops</html>', fixture.replace('TEST-ONLY', 'bad\u0000comment'), fixture.replace('TEST-ONLY', 'bad\rcomment'), fixture.replace('TEST-ONLY', 'bad\u0085comment'), fixture.replace('TEST-ONLY', 'bad\ud800comment')]) {
    await assert.rejects(parsePublicKeys(invalid));
  }
});

test('wrong wire type, truncated fields, trailing data, noncanonical base64, invalid key sizes fail', async () => {
  const wrongType = keyLine('ssh-rsa', keyData);
  const truncated = keyLine('ssh-ed25519', keyData.subarray(0, keyData.length - 1));
  const trailing = keyLine('ssh-ed25519', Buffer.concat([keyData, Buffer.from([0])]));
  const short = keyLine('ssh-ed25519', wire('ssh-ed25519', Buffer.alloc(31)));
  const long = keyLine('ssh-ed25519', wire('ssh-ed25519', Buffer.alloc(33)));
  const badBase64 = 'ssh-ed25519 A===\n';
  const hugeField = keyLine('ssh-ed25519', Buffer.from([255, 255, 255, 255]));
  for (const input of [wrongType, truncated, trailing, short, long, badBase64, hugeField]) await assert.rejects(parsePublicKeys(input));
});

test('public key count and line/input size limits are enforced', async () => {
  await assert.rejects(parsePublicKeys(fixture + secondFixture, {maxKeys: 1}), /Too many/);
  await assert.rejects(parsePublicKeys(fixture.trim() + 'x'.repeat(8192)), /line exceeds/);
  await assert.rejects(parsePublicKeys('#'.repeat(KEY_SOURCE_LIMITS.maxBytes + 1)), /size limit/);
  await assert.rejects(resolveKeys(emptyRelease, () => assert.fail(), {timeoutMs: KEY_SOURCE_LIMITS.timeoutMs + 1}), /limit/);
});

function mpint(bytes) {return bytes[0] & 128 ? Buffer.concat([Buffer.from([0]), bytes]) : bytes;}
function rsaLine(jwk, exponent, modulus) {
  return keyLine('ssh-rsa', wire('ssh-rsa', exponent || mpint(Buffer.from(jwk.e, 'base64url')), modulus || mpint(Buffer.from(jwk.n, 'base64url'))));
}
test('RSA requires complete positive canonical mpints and at least 2048 bits', async () => {
  const {publicKey} = generateKeyPairSync('rsa', {modulusLength: 2048});
  const jwk = publicKey.export({format: 'jwk'});
  assert.equal((await parsePublicKeys(rsaLine(jwk)))[0].type, 'ssh-rsa');
  const modulus = mpint(Buffer.from(jwk.n, 'base64url'));
  for (const [e, n] of [[Buffer.from([0, 3]), modulus], [Buffer.from([128]), modulus], [Buffer.from([2]), modulus], [Buffer.from([1]), modulus], [Buffer.from([3]), Buffer.from([0])], [Buffer.from([3]), Buffer.from([127, 3])], [Buffer.from([3]), modulus.subarray(1)], [Buffer.from([3]), Buffer.concat([Buffer.from([0]), modulus])]]) await assert.rejects(parsePublicKeys(rsaLine(jwk, e, n)));
});

for (const [name, curve] of [['nistp256', 'P-256'], ['nistp384', 'P-384'], ['nistp521', 'P-521']]) {
  test(`ECDSA ${name} requires a matching curve and a valid point`, async () => {
    const {publicKey} = generateKeyPairSync('ec', {namedCurve: curve});
    const jwk = publicKey.export({format: 'jwk'});
    const type = `ecdsa-sha2-${name}`;
    const point = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
    assert.equal((await parsePublicKeys(keyLine(type, wire(type, name, point))))[0].type, type);
    await assert.rejects(parsePublicKeys(keyLine(type, wire(type, 'wrong', point))));
    await assert.rejects(parsePublicKeys(keyLine(type, wire(type, name, point.subarray(1)))));
    const offCurve = Buffer.alloc(point.length); offCurve[0] = 4;
    await assert.rejects(parsePublicKeys(keyLine(type, wire(type, name, offCurve))), /Invalid ECDSA point/);
  });
}

test('OpenSSH security-key Ed25519 and ECDSA formats validate applications and trailing data', async () => {
  const edType = 'sk-ssh-ed25519@openssh.com';
  const publicBytes = keyData.subarray(keyData.length - 32);
  const ed = keyLine(edType, wire(edType, publicBytes, 'ssh:example'));
  assert.equal((await parsePublicKeys(ed))[0].type, edType);
  await assert.rejects(parsePublicKeys(keyLine(edType, wire(edType, publicBytes, ''))));
  await assert.rejects(parsePublicKeys(keyLine(edType, wire(edType, publicBytes, 'ssh:\u0000'))));
  await assert.rejects(parsePublicKeys(keyLine(edType, wire(edType, publicBytes))));
  const {publicKey} = generateKeyPairSync('ec', {namedCurve: 'P-256'});
  const jwk = publicKey.export({format: 'jwk'});
  const ecType = 'sk-ecdsa-sha2-nistp256@openssh.com';
  const point = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
  assert.equal((await parsePublicKeys(keyLine(ecType, wire(ecType, 'nistp256', point, 'ssh:example'))))[0].type, ecType);
});

test('bundle rejects implicit empty and invalid deployment metadata', async () => {
  await assert.rejects(makeKeyBundle([], revision, false));
  await assert.rejects(makeKeyBundle(fixtureKeys, 'not-a-revision', false));
  await assert.rejects(makeKeyBundle(fixtureKeys, revision, 'yes'));
});

test('fallback URL configuration rejects queries, local/private names, and normalized duplicates', () => {
  for (const url of ['https://keys.example.org/key?token=secret', 'https://keys.example.org/key?', 'https://localhost/key', 'https://thing.local/key', 'https://metadata.google.internal/key', 'https://home.lan/key', 'https://192.168.1.1/key', 'https://127.1/key', 'https://[::1]/key', 'https://[2001:db8::1]/key', 'https://2130706433/key', 'https://0x7f000001/key', 'https://single-label/key']) assert.throws(() => validateFallbackSources([url]));
  assert.throws(() => validateFallbackSources(['https://KEYS.example.org:443/key', 'https://keys.example.org/key']), /Duplicate/);
  assert.deepEqual(validateFallbackSources(['https://KEYS.example.org:443/key']), ['https://keys.example.org/key']);
});

test('public-key parser honors an aborted signal before and during validation', async () => {
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(parsePublicKeys(fixture, {signal: controller.signal}), /timeout/);
  let reads = 0;
  const signal = {get aborted() {return ++reads >= 3;}};
  await assert.rejects(parsePublicKeys(fixture + secondFixture, {signal}), /timeout/);
});

test('whole serialized protocol, including metadata, is limited to the client response cap', async () => {
  const text = 'x'.repeat(KEY_SOURCE_LIMITS.maxBytes - 100);
  await assert.rejects(makeKeyBundle([{text}], revision, false), /too-large/);
  const bundle = await makeKeyBundle([{text: 'x'.repeat(KEY_SOURCE_LIMITS.maxBytes - 300)}], revision, false);
  assert.ok(Buffer.byteLength(bundle.text) <= KEY_SOURCE_LIMITS.maxBytes);
});

test('large upstream comments are stripped before publication without leaking labels', async () => {
  const publicBytes = keyData.subarray(keyData.length - 32);
  const lines = Array.from({length: 128}, (_, index) => {
    const bytes = Buffer.from(publicBytes); bytes[31] ^= index;
    const prefix = keyLine('ssh-ed25519', wire('ssh-ed25519', bytes)).trim() + ' ';
    return prefix + 'x'.repeat(8190 - prefix.length) + '\n';
  }).join('');
  assert.ok(Buffer.byteLength(lines) <= KEY_SOURCE_LIMITS.maxBytes);
  const output = await resolveKeys({...emptyRelease, fallbackSources: [urls[0]]}, async () => response(lines));
  assert.equal(output.keyCount, 128);
  assert.ok(output.keysText.length < 20000);
  assert.equal(output.keys[0].label, 'Server key 1');
  const result = await resolveKeys(emptyRelease, async url => response(url === urls[0] ? lines : fixture));
  assert.equal(result.source.url, urls[0]);
  assert.equal(result.keyCount, 128);
});

test('ordinary private-key advice in comments is allowed, while real private formats are rejected anywhere', async () => {
  const advice = '# Do not copy private keys into this repository.\n';
  assert.deepEqual(await parsePublicKeys(advice), []);
  const publicWithComment = fixture.trim().split(/\s+/).slice(0, 2).join(' ') + ' private key remains on my laptop\n';
  assert.equal((await parsePublicKeys(advice + publicWithComment))[0].label, 'private key remains on my laptop');
  for (const marker of ['-----BEGIN OPENSSH PRIVATE KEY-----', '-----BEGIN RSA PRIVATE KEY-----', '-----BEGIN EC PRIVATE KEY-----', '-----BEGIN PRIVATE KEY-----', '-----BEGIN ENCRYPTED PRIVATE KEY-----', 'PuTTY-User-Key-File-3: ssh-ed25519']) {
    await assert.rejects(parsePublicKeys('# ' + marker + '\n' + fixture), /Private keys are never accepted/);
    await assert.rejects(parsePublicKeys(publicWithComment.trim() + ' ' + marker + '\n'), /Private keys are never accepted/);
  }
});

const gistSource = {type:'gist',id:'a'.repeat(32),ownerId:12345,ownerLogin:'original-login',file:'ssh.keys',signatureFile:'ssh.keys.sig',bundleFile:'release.bundle'};
const gistRevision = 'b'.repeat(40);
const gistRelease = {...emptyRelease,keySource:gistSource};
const signedPolicy = {listId:'production',sequence:9,issuedAt:100,expiresAt:300};
const signedDocument = await makeSignedDocument(fixture,signedPolicy);
// Syntactic fixture only, deliberately NOT a valid cryptographic signature. Worker never makes that claim.
const signatureFixture = '-----BEGIN PGP SIGNATURE-----\n\nYWJj\n-----END PGP SIGNATURE-----\n';
const signedBundleFixture = signedDocument + SIGNATURE_SEPARATOR + signatureFixture;
const gistFile = (filename,content) => ({filename,content,size:Buffer.byteLength(content),truncated:false,encoding:'utf-8',raw_url:'https://untrusted.invalid/ignored'});
const gistData = (files={}) => ({id:gistSource.id,owner:{id:gistSource.ownerId,login:'renamed-login'},public:true,truncated:false,history:[{version:gistRevision}],files});
const jsonResponse = data => response(JSON.stringify(data));
const gistUrl = `https://api.github.com/gists/${gistSource.id}`;

for (const status of [201,204,206]) test(`non-200 success HTTP ${status} is not a key release`, async () => {
  const result=await resolveKeys(emptyRelease,async url=>url===urls[0]?new Response(status===204?null:fixture,{status}):response(fixture));
  assert.equal(result.source.url,urls[1]);
});

test('Git signed document is authoritative and exact, while missing/bad signature does not block OFF', async () => {
  for (const signature of [null,'bad armor',signatureFixture]) {
    const result=await resolveKeys({...emptyRelease,keys:fixtureKeys,signedDocument,signature},()=>assert.fail('No network'));
    assert.equal(result.keysText,signedDocument); assert.equal(result.signedDocument,signedDocument);
    assert.equal(result.signature,signature===signatureFixture?signatureFixture:null);
    assert.equal(result.keyRevision,hash(signedDocument)); assert.equal(result.sha256,hash(canonical));
    assert.equal(result.signedMetadata.sequence,9);
  }
});

test('signed empty revocation suppresses fallback even when legacy allowEmpty is false', async () => {
  const document=await makeSignedDocument('',{...signedPolicy,revoke:true});
  const result=await resolveKeys({...emptyRelease,signedDocument:document,signature:signatureFixture},()=>assert.fail('Revocation must not fetch'));
  assert.equal(result.keyCount,0);assert.equal(result.allowEmpty,true);assert.equal(result.source.type,'explicit-empty');
  assert.equal(result.keysText,document);
});

test('strict sources never downgrade to raw keys; ordered signed fallback chooses one entire bundle', async () => {
  const visited=[];
  const result=await resolveKeys({...emptyRelease,keys:fixtureKeys},async url=>{visited.push(url);return response(url===urls[0]?fixture:signedBundleFixture);},{requireSigned:true,now:200});
  assert.deepEqual(visited,urls.slice(0,2));assert.equal(result.source.url,urls[1]);assert.equal(result.signature,signatureFixture);
  assert.equal(result.keysText,signedDocument);assert.equal(result.signedBundle,signedBundleFixture);
});

test('fallback standalone signed document gets only its same-source detached signature', async () => {
  const visited=[];
  const result=await resolveKeys(emptyRelease,async url=>{visited.push(url);return response(url.endsWith('.sig')?signatureFixture:signedDocument);},{requireSigned:true,now:200});
  assert.deepEqual(visited,[urls[0],urls[0]+'.sig']);assert.equal(result.signature,signatureFixture);assert.equal(result.keysText,signedDocument);
});

test('missing, non200, malformed or hung optional signature still serves the valid OFF document', async () => {
  for (const mode of ['missing','non200','bad','fetch-timeout','body-timeout']) {
    let cancelled=false;
    const body=new ReadableStream({start(c){c.enqueue(new TextEncoder().encode('part'));},cancel(){cancelled=true;}});
    const fetcher=async url=> {
      if (!url.endsWith('.sig')) return response(signedDocument);
      if(mode==='missing')return new Response('missing',{status:404});
      if(mode==='non200')return new Response(signatureFixture,{status:206});
      if(mode==='bad')return response('bad');
      if(mode==='fetch-timeout')return new Promise(()=>{});
      return new Response(body);
    };
    const result=await resolveKeys(emptyRelease,fetcher,{timeoutMs:20});
    assert.equal(result.keysText,signedDocument,mode);assert.equal(result.signature,null,mode);
    if(mode==='body-timeout')assert.equal(cancelled,true);
  }
});

test('strict signature failure stays with its source before trying next whole signed release', async () => {
  const result=await resolveKeys(emptyRelease,async url=>url===urls[0]?response(signedDocument):url===urls[0]+'.sig'?new Response('',{status:404}):response(signedBundleFixture),{requireSigned:true,now:200});
  assert.equal(result.source.url,urls[1]);assert.equal(result.signedBundle,signedBundleFixture);
});

test('Gist fetch uses numeric-owner pin and immutable revision, never latest contents or raw_url', async () => {
  const visited=[];
  const result=await resolveKeys(gistRelease,async (url,init)=>{
    visited.push(url);assert.equal(init.headers['User-Agent'],'conf-sshd-key-source');assert.equal(init.redirect,'manual');assert.equal(init.cache,'no-store');
    if(url===gistUrl)return jsonResponse(gistData({'ssh.keys':gistFile('ssh.keys',secondFixture)}));
    assert.equal(url,gistUrl+'/'+gistRevision);
    return jsonResponse(gistData({'ssh.keys':gistFile('ssh.keys',fixture)}));
  });
  assert.deepEqual(visited,[gistUrl,gistUrl+'/'+gistRevision]);
  assert.equal(result.sha256,hash(canonical));assert.equal(result.source.type,'gist');assert.equal(result.source.ownerId,12345);
  assert.equal(result.source.ownerLogin,'original-login');assert.equal(result.source.gistRevision,gistRevision);
  assert.equal(result.signature,null);
});

test('Gist signed document and signature are extracted from one pinned revision without transforms', async () => {
  let calls=0;
  const result=await resolveKeys(gistRelease,async url=>{calls++;return jsonResponse(gistData(url===gistUrl?{}:{'ssh.keys':gistFile('ssh.keys',signedDocument),'ssh.keys.sig':gistFile('ssh.keys.sig',signatureFixture)}));},{requireSigned:true,now:200});
  assert.equal(calls,2);assert.equal(result.keysText,signedDocument);assert.equal(result.signature,signatureFixture);assert.equal(result.keyRevision,hash(signedDocument));
});

test('Gist bundle has one authoritative document and explicit revocation cannot be refilled', async () => {
  const revoke=await makeSignedDocument('',{...signedPolicy,revoke:true});
  const bundle=revoke+SIGNATURE_SEPARATOR+signatureFixture;
  const result=await resolveKeys(gistRelease,async url=>{assert.ok(url.startsWith(gistUrl));return jsonResponse(gistData({'release.bundle':gistFile('release.bundle',bundle),'ssh.keys':gistFile('ssh.keys',fixture)}));});
  assert.equal(result.keyCount,0);assert.equal(result.allowEmpty,true);assert.equal(result.keysText,revoke);assert.equal(result.source.file,'release.bundle');
});

test('missing/truncated/malformed Gist signature does not prevent an OFF document response', async () => {
  for(const optional of [null,gistFile('ssh.keys.sig','bad'),{...gistFile('ssh.keys.sig',signatureFixture),truncated:true}]) {
    const result=await resolveKeys(gistRelease,async()=>jsonResponse(gistData({'ssh.keys':gistFile('ssh.keys',signedDocument),...(optional?{'ssh.keys.sig':optional}:{})})));
    assert.equal(result.keysText,signedDocument);assert.equal(result.signature,null);
  }
});

for (const when of ['latest','revision']) test(`Gist owner mismatch in ${when} fails closed before ordered fallback`, async () => {
  const visited=[];
  const result=await resolveKeys(gistRelease,async url=>{
    visited.push(url);
    if(url===urls[0])return response(fixture);
    const data=gistData({'ssh.keys':gistFile('ssh.keys',fixture)});
    if((when==='latest')===(url===gistUrl))data.owner.id=99999;
    return jsonResponse(data);
  });
  assert.equal(result.source.type,'fallback');assert.equal(visited.length,when==='latest'?2:3);
});

test('Gist rejects top-level truncation, private sources, invalid revision, selected-file truncation and byte mismatches', async () => {
  const mutations=[data=>{data.truncated=true;},data=>{data.public=false;},data=>{data.history[0].version='../latest';},data=>{data.files['ssh.keys'].truncated=true;},data=>{data.files['ssh.keys'].size++;},data=>{data.files['ssh.keys'].filename='different';},data=>{data.files['ssh.keys'].encoding='base64';},data=>{data.id='b'.repeat(32);}];
  for(const mutate of mutations){
    const result=await resolveKeys(gistRelease,async url=>{if(url===urls[0])return response(fixture);const data=gistData({'ssh.keys':gistFile('ssh.keys',fixture)});mutate(data);return jsonResponse(data);});
    assert.equal(result.source.type,'fallback');
  }
});

test('Gist combined metadata/revision HTTP/body timeout is bounded and falls back without stale keys', async () => {
  for(const mode of ['http','json','fetch','body']) {
    let cancelled=false;
    const body=new ReadableStream({start(c){c.enqueue(new TextEncoder().encode('{'));},cancel(){cancelled=true;}});
    const result=await resolveKeys(gistRelease,async url=>{
      if(url===urls[0])return response(fixture);
      if(url===gistUrl)return jsonResponse(gistData());
      if(mode==='http')return new Response('',{status:503});
      if(mode==='json')return response('{');
      if(mode==='fetch')return new Promise(()=>{});
      return new Response(body);
    },{timeoutMs:20});
    assert.equal(result.source.type,'fallback');if(mode==='body')assert.equal(cancelled,true);
  }
});

test('Gist dynamic revision changes content digest while code revision stays fixed', async () => {
  let current=gistRevision, text=fixture;
  const fetcher=async url=>{const data=gistData({'ssh.keys':gistFile('ssh.keys',text)});data.history[0].version=current;assert.ok(url===gistUrl||url===gistUrl+'/'+current);return jsonResponse(data);};
  const first=await resolveKeys(gistRelease,fetcher);
  current='c'.repeat(40);text=secondFixture;
  const second=await resolveKeys(gistRelease,fetcher);
  assert.notEqual(first.sha256,second.sha256);assert.notEqual(first.source.gistRevision,second.source.gistRevision);assert.equal(first.revision,second.revision);
});

test('invalid Gist and signing config is rejected before any network request', async () => {
  for(const keySource of [null,{type:'other'},{type:'git',url:'https://evil.example'}, {...gistSource,ownerId:'12345'}, {...gistSource,ownerId:0}, {...gistSource,id:'../escape'}, {...gistSource,ownerLogin:'bad/login'}, {...gistSource,file:'../key'}, {...gistSource,signatureFile:'ssh.keys'}, {...gistSource,token:'secret'}]) await assert.rejects(resolveKeys({...gistRelease,keySource},()=>assert.fail('Invalid config must not fetch')));
});

test('Gist response bytes are bounded and no fallback response inherits upstream text or private data', async () => {
  const result=await resolveKeys(gistRelease,async url=>url===urls[0]?response(fixture):new Response('{}',{headers:{'Content-Length':String(2*SIGNED_BUNDLE_MAX_BYTES+1)}}));
  assert.equal(result.source.type,'fallback');assert.doesNotMatch(JSON.stringify(result),/TEST-ONLY/);
});

test('named Gist bundles cannot silently downgrade to raw key files', async () => {
  for(const contents of [fixture,signedDocument]) {
    const result=await resolveKeys(gistRelease,async url=>url===urls[0]?response(fixture):jsonResponse(gistData({'release.bundle':gistFile('release.bundle',contents)})));
    assert.equal(result.source.type,'fallback');
  }
});

test('only an existing ASCII-whitespace-empty primary file expresses unsigned revocation', () => {
  for (const input of ['', ' \t\r\n\n ']) assert.equal(isExplicitEmptyKeyFile(input), true);
  for (const input of [null, undefined, 0, '# initial placeholder\n', '\u00a0', '\u0000', '\u000b', fixture]) assert.equal(isExplicitEmptyKeyFile(input), false);
});

for (const filename of ['ssh.keys', 'release.bundle']) {
  for (const input of ['', ' \t\r\n\n ']) {
    test(`blank pinned Gist ${filename} revokes without any fallback (${JSON.stringify(input)})`, async () => {
      const visited = [];
      const result = await resolveKeys(gistRelease, async url => {
        visited.push(url);
        assert.ok(url === gistUrl || url === gistUrl + '/' + gistRevision);
        return jsonResponse(gistData({[filename]: gistFile(filename, input)}));
      }, {requirePrimary: true});
      assert.deepEqual(visited, [gistUrl, gistUrl + '/' + gistRevision]);
      assert.equal(result.keyCount, 0); assert.equal(result.allowEmpty, true);
      assert.equal(result.source.type, 'gist'); assert.equal(result.source.file, filename);
      assert.equal(result.source.gistRevision, gistRevision);
      assert.equal(result.sha256, hash(''));
      assert.match(result.keysText, /# key-count 0\n# allow-empty yes\n/);
      assert.equal(result.signedDocument, null); assert.equal(result.signature, null);
    });
  }
}

test('blank Gist primary and Git primary cannot be replaced with a strict signed fallback', async () => {
  for (const filename of ['ssh.keys', 'release.bundle']) {
    const visited = [];
    const error = await unavailable(async url => {
      visited.push(url);
      if (!url.startsWith(gistUrl)) return response(signedBundleFixture);
      return jsonResponse(gistData({[filename]: gistFile(filename, '')}));
    }, {requireSigned: true, now: 200}, gistRelease);
    assert.deepEqual(visited, [gistUrl, gistUrl + '/' + gistRevision]);
    assert.deepEqual(error.diagnostics, [{index: -1, code: 'unsigned-revocation'}]);
    assert.equal(error.failureKind, 'validation');
  }
  const error = await unavailable(() => assert.fail('Unsigned Git revocation must not fetch fallback'), {requireSigned: true}, {...emptyRelease, allowEmpty: true});
  assert.equal(error.diagnostics[0].code, 'unsigned-revocation');
});

test('conflicting blank and nonblank Gist formats fail closed without fallback', async () => {
  for (const [split, bundle] of [['', signedBundleFixture], [fixture, ''], ['# placeholder\n', ''], ['', 'invalid bundle']]) {
    for (const options of [{}, {requireSigned: true, now: 200}, {requirePrimary: true}]) {
      const visited = [];
      const error = await unavailable(async url => {
        visited.push(url);
        if (!url.startsWith(gistUrl)) return response(fixture);
        return jsonResponse(gistData({'ssh.keys': gistFile('ssh.keys', split), 'release.bundle': gistFile('release.bundle', bundle)}));
      }, options, gistRelease);
      assert.deepEqual(visited, [gistUrl, gistUrl + '/' + gistRevision]);
      assert.deepEqual(error.diagnostics, [{index: -1, code: 'ambiguous-empty-primary'}]);
    }
  }
});

test('a validated Gist clear still blocks fallback when the competing format is malformed', async () => {
  for (const emptyName of ['ssh.keys', 'release.bundle']) {
    const otherName = emptyName === 'ssh.keys' ? 'release.bundle' : 'ssh.keys';
    const error = await unavailable(async url => {
      assert.ok(url.startsWith(gistUrl), 'Known clear must not fetch a fallback');
      return jsonResponse(gistData({[emptyName]: gistFile(emptyName, ''), [otherName]: {...gistFile(otherName, fixture), truncated: true}}));
    }, {}, gistRelease);
    assert.equal(error.diagnostics[0].code, 'ambiguous-empty-primary');
  }
});

test('both validated blank Gist formats express the same clear', async () => {
  const result = await resolveKeys(gistRelease, async url => {
    assert.ok(url.startsWith(gistUrl));
    return jsonResponse(gistData({'ssh.keys': gistFile('ssh.keys', ''), 'release.bundle': gistFile('release.bundle', '\n')}));
  });
  assert.equal(result.keyCount, 0); assert.equal(result.allowEmpty, true);
});

test('empty latest Gist contents never override its pinned nonempty revision', async () => {
  const result = await resolveKeys(gistRelease, async url => {
    assert.ok(url.startsWith(gistUrl));
    return jsonResponse(gistData({'ssh.keys': gistFile('ssh.keys', url === gistUrl ? '' : fixture)}));
  });
  assert.equal(result.keyCount, 1); assert.equal(result.allowEmpty, false);
});

test('missing, comments-only and untrusted Gist primaries never synthesize a clear', async () => {
  const cases = [
    () => gistData(),
    () => gistData({'ssh.keys': gistFile('ssh.keys', '# initial placeholder\n\n')}),
    () => ({...gistData({'ssh.keys': gistFile('ssh.keys', '')}), owner: {id: 999}}),
    () => ({...gistData({'ssh.keys': gistFile('ssh.keys', '')}), history: [{version: '../invalid'}]}),
    () => gistData({'ssh.keys': {...gistFile('ssh.keys', ''), size: 1}}),
    () => gistData({'ssh.keys': {...gistFile('ssh.keys', ''), truncated: true}}),
  ];
  for (const data of cases) {
    const result = await resolveKeys(gistRelease, async url => url.startsWith(gistUrl) ? jsonResponse(data()) : response(fixture));
    assert.equal(result.source.type, 'fallback'); assert.equal(result.keyCount, 1); assert.equal(result.allowEmpty, false);
    const error = await unavailable(async url => {
      assert.ok(url.startsWith(gistUrl), 'Primary preflight cannot fetch fallback');
      return jsonResponse(data());
    }, {requirePrimary: true}, gistRelease);
    assert.equal(error.failureKind, 'validation');
  }
});

test('owner validation also precedes clear at the pinned Gist revision', async () => {
  const error = await unavailable(async url => {
    assert.ok(url.startsWith(gistUrl));
    const data = gistData({'ssh.keys': gistFile('ssh.keys', '')});
    if (url !== gistUrl) data.owner.id = 999;
    return jsonResponse(data);
  }, {requirePrimary: true}, gistRelease);
  assert.deepEqual(error.diagnostics, [{index: -1, code: 'gist-owner-mismatch'}]);
});

test('Gist HTTP and network failure never clear and cannot be hidden by preflight fallback', async () => {
  for (const mode of ['404', '503', 'network']) {
    const fetcher = async url => {
      if (!url.startsWith(gistUrl)) return response(fixture);
      if (mode === 'network') throw Error('SECRET network information');
      return new Response('', {status: Number(mode)});
    };
    const result = await resolveKeys(gistRelease, fetcher);
    assert.equal(result.source.type, 'fallback'); assert.equal(result.allowEmpty, false);
    const visited = [];
    const error = await unavailable(async url => {visited.push(url); return fetcher(url);}, {requirePrimary: true}, gistRelease);
    assert.deepEqual(visited, [gistUrl]); assert.equal(error.failureKind, 'retrieval');
    assert.doesNotMatch(JSON.stringify(error), /SECRET|https:/);
  }
});

test('primary-only preflight accepts signed revocation and rejects missing, malformed or unsigned Git primary', async () => {
  const document = await makeSignedDocument('', {...signedPolicy, revoke: true});
  const signed = {...emptyRelease, signedDocument: document, signature: signatureFixture};
  const result = await resolveKeys(signed, () => assert.fail('No fetch'), {requirePrimary: true, requireSigned: true, now: 200});
  assert.equal(result.keyCount, 0); assert.equal(result.allowEmpty, true);
  for (const [release, options, code] of [
    [emptyRelease, {}, 'unconfigured-primary'],
    [{...emptyRelease, signedDocument: 'invalid'}, {}, 'invalid-signed-release'],
    [{...emptyRelease, keys: fixtureKeys}, {requireSigned: true}, 'invalid-signed-release'],
    [{...emptyRelease, allowEmpty: true}, {requireSigned: true}, 'unsigned-revocation'],
  ]) {
    const error = await unavailable(() => assert.fail('Preflight must not fetch'), {requirePrimary: true, ...options}, release);
    assert.equal(error.diagnostics[0].code, code);
  }
  await assert.rejects(resolveKeys(emptyRelease, () => assert.fail('Invalid option must not fetch'), {requirePrimary: 'yes'}), /requirePrimary must be boolean/);
});

test('empty arbitrary fallback remains unavailable, including whitespace and comments', async () => {
  for (const body of ['', ' \t\r\n', '# placeholder\n']) {
    const error = await unavailable(async () => response(body), {}, {...emptyRelease, fallbackSources: [urls[0]]});
    assert.equal(error.diagnostics[0].code, 'empty'); assert.equal(error.failureKind, 'validation');
  }
});

test('failed-source retry classification retains any retrieval error even beyond bounded diagnostics', async () => {
  for (const code of ['network-error', 'timeout', 'http-error', 'redirect']) {
    const error = new FallbackUnavailableError([...Array.from({length: 5}, (_, index) => ({index, code: 'invalid-keys'})), {index: 5, code, status: 404}]);
    assert.equal(error.failureKind, 'retrieval'); assert.equal(error.diagnostics.length, 5);
  }
  assert.equal(new FallbackUnavailableError([{index: -1, code: 'invalid-signed-release'}, {index: 0, code: 'empty'}]).failureKind, 'validation');
});

test('a stale detached signature does not turn a blank Gist file into a key-bearing conflict', async () => {
  for (const signature of [signatureFixture, 'bad old signature']) {
    const fetcher = async url => {
      assert.ok(url.startsWith(gistUrl), 'Blank primary must not fetch fallback');
      return jsonResponse(gistData({'ssh.keys': gistFile('ssh.keys', ''), 'ssh.keys.sig': gistFile('ssh.keys.sig', signature)}));
    };
    const result = await resolveKeys(gistRelease, fetcher, {requirePrimary: true});
    assert.equal(result.keyCount, 0); assert.equal(result.allowEmpty, true);
    assert.equal(result.signature, null); assert.equal(result.signedDocument, null);
    const error = await unavailable(fetcher, {requirePrimary: true, requireSigned: true, now: 200}, gistRelease);
    assert.equal(error.diagnostics[0].code, 'unsigned-revocation');
  }
});

test('strict primary-only Gist preflight accepts an existing signed-format revocation unchanged', async () => {
  const document = await makeSignedDocument('', {...signedPolicy, revoke: true});
  const result = await resolveKeys(gistRelease, async url => {
    assert.ok(url.startsWith(gistUrl));
    return jsonResponse(gistData({'ssh.keys': gistFile('ssh.keys', document), 'ssh.keys.sig': gistFile('ssh.keys.sig', signatureFixture)}));
  }, {requirePrimary: true, requireSigned: true, now: 200});
  assert.equal(result.keyCount, 0); assert.equal(result.allowEmpty, true);
  assert.equal(result.keysText, document); assert.equal(result.signature, signatureFixture);
  assert.equal(result.signedMetadata.sequence, signedPolicy.sequence);
});
