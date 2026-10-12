import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash, generateKeyPairSync} from 'node:crypto';
import {FallbackUnavailableError, KEY_SOURCE_LIMITS, makeKeyBundle, parsePublicKeys, resolveKeys, validateFallbackSources} from '../cf-worker/src/key-source.js';

const fixture = await readFile(new URL('./fixtures/keys.pub', import.meta.url), 'utf8');
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
  assert.equal(result.sha256, hash(fixture));
  assert.equal(result.keyRevision, result.sha256);
  assert.equal(result.keysText, `# conf-sshd-v1\n# revision ${revision}\n# key-count 1\n# allow-empty no\n# sha256 ${hash(fixture)}\n# end-metadata\n${fixture}`);
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
  assert.equal(result.sha256, hash(fixture));
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
  assert.equal(result.sha256, hash(secondFixture));
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
  const error = await unavailable(async () => new Response(fixture, {headers: {'Content-Length': String(KEY_SOURCE_LIMITS.maxBytes + 1)}}), {}, {...emptyRelease, fallbackSources: [urls[0]]});
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
  assert.equal(bundle.sha256, hash(key.text + '\n'));
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

test('an upstream fitting the input cap but exceeding the serialized output cap is skipped', async () => {
  const publicBytes = keyData.subarray(keyData.length - 32);
  const lines = Array.from({length: 128}, (_, index) => {
    const bytes = Buffer.from(publicBytes); bytes[31] ^= index;
    const prefix = keyLine('ssh-ed25519', wire('ssh-ed25519', bytes)).trim() + ' ';
    return prefix + 'x'.repeat(8190 - prefix.length) + '\n';
  }).join('');
  assert.ok(Buffer.byteLength(lines) <= KEY_SOURCE_LIMITS.maxBytes);
  const error = await unavailable(async () => response(lines), {}, {...emptyRelease, fallbackSources: [urls[0]]});
  assert.equal(error.diagnostics[0].code, 'too-large');
  const result = await resolveKeys(emptyRelease, async url => response(url === urls[0] ? lines : fixture));
  assert.equal(result.source.url, urls[1]);
  assert.equal(result.sha256, hash(fixture));
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
