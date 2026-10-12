// Runtime fallback is deliberately stateless: a request never reuses earlier keys.
export const KEY_SOURCE_LIMITS = Object.freeze({sources: 5, timeoutMs: 3000, maxBytes: 1024 * 1024, maxKeys: 1000});
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', {fatal: true});
const keyTypes = new Set(['ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'sk-ssh-ed25519@openssh.com', 'sk-ecdsa-sha2-nistp256@openssh.com']);
const curves = {nistp256: {name: 'P-256', size: 32}, nistp384: {name: 'P-384', size: 48}, nistp521: {name: 'P-521', size: 66}};

class SourceError extends Error {
  constructor(code, status) { super(code); this.code = code; if (status !== undefined) this.status = status; }
}
export class FallbackUnavailableError extends Error {
  constructor(diagnostics = []) {
    super('No configured SSH key source returned a valid nonempty key set.');
    this.name = 'FallbackUnavailableError';
    this.code = 'KEY_SOURCES_UNAVAILABLE';
    // Keep diagnostics safe to log or return: no response content, URL secrets, or exception text.
    this.diagnostics = diagnostics.slice(0, KEY_SOURCE_LIMITS.sources).map(({index, code, status}) => ({index, code, ...(status === undefined ? {} : {status})}));
  }
}

export function validateFallbackSources(sources = []) {
  if (!Array.isArray(sources) || sources.length > KEY_SOURCE_LIMITS.sources) throw new Error('fallbackSources must contain at most five HTTPS URLs.');
  const seen = new Set();
  return sources.map(value => {
    if (typeof value !== 'string' || value.length > 2048 || /[\s\u0000-\u001f\u007f-\u009f]/u.test(value)) throw new Error('Each fallback source must be a public-host HTTPS URL without credentials, queries, or fragments.');
    let url;
    try { url = new URL(value); } catch { throw new Error('Invalid fallback source URL.'); }
    if (url.protocol !== 'https:' || !url.hostname || url.username || url.password || url.search || value.includes('?') || url.hash || value.includes('#') || !value.startsWith('https://')) throw new Error('Each fallback source must be a public-host HTTPS URL without credentials, queries, or fragments.');
    // Configuration is trusted, but exclude local names and IP literals before any network call.
    // A hostname allowlist is not a DNS-resolution guarantee; source operators remain trusted.
    if (url.hostname.length > 253 || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(url.hostname) || /\.(?:localhost|local|localdomain|internal|intranet|lan|home|corp|onion)$/i.test(url.hostname)) throw new Error('Fallback sources must use public HTTPS hostnames, not local names or IP addresses.');
    if (seen.has(url.href)) throw new Error('Duplicate fallback source URL.');
    seen.add(url.href);
    return url.href;
  });
}

function encodeBase64(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
function decodeBase64(encoded) {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded) || encoded.length % 4 === 1) throw new Error('Invalid public key encoding.');
  let decoded;
  try { decoded = Uint8Array.from(atob(encoded), c => c.charCodeAt(0)); } catch { throw new Error('Invalid public key encoding.'); }
  if (encodeBase64(decoded).replace(/=+$/, '') !== encoded.replace(/=+$/, '')) throw new Error('Invalid public key encoding.');
  return decoded;
}
async function sha256(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)); }
function hex(bytes) { return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join(''); }

class WireReader {
  constructor(bytes) { this.bytes = bytes; this.offset = 0; }
  string() {
    if (this.offset + 4 > this.bytes.length) throw new Error('Truncated public key data.');
    const length = new DataView(this.bytes.buffer, this.bytes.byteOffset + this.offset, 4).getUint32(0);
    this.offset += 4;
    if (length > this.bytes.length - this.offset) throw new Error('Truncated public key field.');
    const value = this.bytes.subarray(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }
  text() { return decoder.decode(this.string()); }
  end() { if (this.offset !== this.bytes.length) throw new Error('Unexpected trailing public key data.'); }
}
function positiveMpint(bytes) {
  if (!bytes.length || (bytes[0] & 128) || (bytes[0] === 0 && (bytes.length === 1 || !(bytes[1] & 128)))) throw new Error('RSA fields must be positive, minimally encoded mpints.');
  return bytes[0] === 0 ? bytes.subarray(1) : bytes;
}
async function validatePoint(reader, curveName) {
  if (reader.text() !== curveName) throw new Error('ECDSA curve does not match key type.');
  const point = reader.string(), curve = curves[curveName];
  if (point.length !== 1 + 2 * curve.size || point[0] !== 4) throw new Error('Invalid uncompressed ECDSA point.');
  // Web Crypto also rejects off-curve points, rather than just checking wire lengths.
  try { await crypto.subtle.importKey('raw', point, {name: 'ECDSA', namedCurve: curve.name}, false, ['verify']); }
  catch { throw new Error('Invalid ECDSA point.'); }
}
function validateApplication(reader) {
  const value = reader.string();
  if (!value.length || value.length > 1024 || /[\u0000-\u001f\u007f-\u009f]/u.test(decoder.decode(value))) throw new Error('Invalid security-key application.');
}
async function validateWire(type, bytes) {
  const reader = new WireReader(bytes);
  if (reader.text() !== type) throw new Error('Public key type does not match key data.');
  if (type === 'ssh-ed25519' || type === 'sk-ssh-ed25519@openssh.com') {
    if (reader.string().length !== 32) throw new Error('Ed25519 public keys must contain 32 bytes.');
    if (type.startsWith('sk-')) validateApplication(reader);
  } else if (type === 'ssh-rsa') {
    const e = positiveMpint(reader.string()), n = positiveMpint(reader.string());
    const bits = (n.length - 1) * 8 + 32 - Math.clz32(n[0]);
    if (bits < 2048 || bits > 16384) throw new Error('RSA keys must have 2048 to 16384 bits.');
    if (e.length > 8 || (e.length === 1 && e[0] < 3) || !(e.at(-1) & 1) || !(n.at(-1) & 1)) throw new Error('Invalid RSA exponent or modulus.');
  } else if (type.startsWith('ecdsa-sha2-')) {
    await validatePoint(reader, type.slice('ecdsa-sha2-'.length));
  } else if (type === 'sk-ecdsa-sha2-nistp256@openssh.com') {
    await validatePoint(reader, 'nistp256');
    validateApplication(reader);
  } else throw new Error('Unsupported public key type.');
  reader.end();
}

/** Parse plain OpenSSH keys, never authorized_keys options, certificates, or executable content. */
export async function parsePublicKeys(input, {maxKeys = KEY_SOURCE_LIMITS.maxKeys, signal} = {}) {
  if (signal?.aborted) throw new SourceError('timeout');
  if (!Number.isInteger(maxKeys) || maxKeys < 1 || maxKeys > KEY_SOURCE_LIMITS.maxKeys) throw new Error('Invalid public key count limit.');
  if (typeof input !== 'string' || encoder.encode(input).length > KEY_SOURCE_LIMITS.maxBytes) throw new Error('Public key input exceeds its size limit.');
  const normalized = input.replace(/\r\n/g, '\n');
  if (/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\ufffd]/u.test(normalized) || /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(normalized)) throw new Error('Public key input contains invalid control characters or Unicode.');
  if (/-----BEGIN [^-\r\n]*PRIVATE KEY-----|PuTTY-User-Key-File-[0-9]+:/i.test(normalized)) throw new Error('Private keys are never accepted.');
  const keys = [], seen = new Set();
  for (const raw of normalized.split('\n')) {
    if (signal?.aborted) throw new SourceError('timeout');
    const line = raw.replace(/^[ \t]+|[ \t]+$/g, '');
    if (!line || line.startsWith('#')) continue;
    if (encoder.encode(line).length > 8192) throw new Error('Public key line exceeds its size limit.');
    const match = /^(\S+)[ \t]+([A-Za-z0-9+/]+={0,2})(?:[ \t]+(.*))?$/u.exec(line);
    if (!match || !keyTypes.has(match[1])) throw new Error('Expected a supported plain OpenSSH public key without options or certificates.');
    if (keys.length >= maxKeys) throw new Error('Too many public keys.');
    const [, type, encoded, rawComment = ''] = match;
    const comment = rawComment.replace(/[ \t]+/g, ' ').trim();
    const bytes = decodeBase64(encoded), identity = encodeBase64(bytes);
    if (seen.has(identity)) throw new Error('Duplicate public key.');
    await validateWire(type, bytes);
    if (signal?.aborted) throw new SourceError('timeout');
    seen.add(identity);
    keys.push({text: `${type} ${identity}${comment ? ` ${comment}` : ''}`, type, label: comment || `Server key ${keys.length + 1}`, fingerprint: `SHA256:${encodeBase64(await sha256(bytes)).replace(/=+$/, '')}`});
  }
  return keys;
}

export async function makeKeyBundle(keys, revision, allowEmpty) {
  if (!/^[0-9a-f]{40}$/.test(revision)) throw new Error('Release revision must be a 40-character Git commit SHA.');
  if (typeof allowEmpty !== 'boolean') throw new Error('allowEmpty must be an explicit boolean.');
  if (!keys.length && !allowEmpty) throw new Error('An empty key set requires explicit revocation.');
  const payload = keys.map(key => `${key.text}\n`).join('');
  const digest = hex(await sha256(encoder.encode(payload)));
  const text = `# conf-sshd-v1\n# revision ${revision}\n# key-count ${keys.length}\n# allow-empty ${allowEmpty ? 'yes' : 'no'}\n# sha256 ${digest}\n# end-metadata\n${payload}`;
  if (encoder.encode(text).length > KEY_SOURCE_LIMITS.maxBytes) throw new SourceError('too-large');
  return {sha256: digest, text};
}
async function snapshot(keys, release, source) {
  const bundle = await makeKeyBundle(keys, release.revision, release.allowEmpty);
  return {keys, keysText: bundle.text, sha256: bundle.sha256, keyCount: keys.length, allowEmpty: release.allowEmpty, source, revision: release.revision, keyRevision: bundle.sha256, fetchedAt: new Date().toISOString()};
}
function boundedOption(options, name) {
  const value = options[name] ?? KEY_SOURCE_LIMITS[name];
  if (!Number.isInteger(value) || value < 1 || value > KEY_SOURCE_LIMITS[name]) throw new Error(`Invalid ${name} limit.`);
  return value;
}
async function readBody(response, signal, maxBytes) {
  const declaredLength = response.headers.get('Content-Length');
  if (declaredLength && /^\d+$/.test(declaredLength) && Number(declaredLength) > maxBytes) throw new SourceError('too-large');
  if (!response.body) return '';
  const reader = response.body.getReader();
  // Grow one bounded buffer, so an upstream sending tiny chunks cannot grow an unbounded chunk list.
  let bytes = new Uint8Array(Math.min(16384, maxBytes));
  let total = 0, complete = false;
  const cancel = () => { void reader.cancel().catch(() => {}); };
  signal.addEventListener('abort', cancel, {once: true});
  try {
    while (true) {
      if (signal.aborted) throw new SourceError('timeout');
      const {value, done} = await reader.read();
      if (signal.aborted) throw new SourceError('timeout');
      if (done) { complete = true; break; }
      const nextTotal = total + value.byteLength;
      if (nextTotal > maxBytes) throw new SourceError('too-large');
      if (nextTotal > bytes.length) {
        const expanded = new Uint8Array(Math.min(maxBytes, Math.max(nextTotal, bytes.length * 2)));
        expanded.set(bytes);
        bytes = expanded;
      }
      bytes.set(value, total);
      total = nextTotal;
    }
    try { return decoder.decode(bytes.subarray(0, total)); } catch { throw new SourceError('invalid-utf8'); }
  } finally {
    signal.removeEventListener('abort', cancel);
    if (!complete) cancel();
    reader.releaseLock();
  }
}
async function fetchSource(url, fetchImpl, limits) {
  const controller = new AbortController();
  let timer, response;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => { reject(new SourceError('timeout')); controller.abort(); }, limits.timeoutMs);
  });
  const operation = (async () => {
    try {
      response = await fetchImpl(url, {method: 'GET', redirect: 'manual', cache: 'no-store', headers: {'Accept': 'text/plain, application/octet-stream;q=0.9', 'Cache-Control': 'no-cache, no-store', 'Pragma': 'no-cache'}, signal: controller.signal});
      if (controller.signal.aborted) throw new SourceError('timeout');
      if (response.redirected || (response.status >= 300 && response.status < 400)) throw new SourceError('redirect', response.status);
      if (!response.ok) throw new SourceError('http-error', response.status);
      const body = await readBody(response, controller.signal, limits.maxBytes);
      let keys;
      try { keys = await parsePublicKeys(body, {maxKeys: limits.maxKeys, signal: controller.signal}); } catch { throw new SourceError('invalid-keys'); }
      if (!keys.length) throw new SourceError('empty');
      return keys;
    } finally {
      if (response?.body && !response.body.locked) void response.body.cancel().catch(() => {});
    }
  })();
  try { return await Promise.race([operation, timeout]); }
  finally { clearTimeout(timer); }
}

/** Only release-configured URLs are accepted; callers must never derive release data from a request. */
export async function resolveKeys(release, fetchImpl = globalThis.fetch, internalOptions = {}) {
  if (!release || !Array.isArray(release.keys) || typeof release.allowEmpty !== 'boolean') throw new Error('Invalid deployed key release.');
  if (release.keys.length) return snapshot(release.keys, release, {type: 'repository'});
  // An explicit empty release means revoke. It must never be repopulated from a fallback.
  if (release.allowEmpty) return snapshot([], release, {type: 'explicit-empty'});
  const sources = validateFallbackSources(release.fallbackSources);
  const limits = {timeoutMs: boundedOption(internalOptions, 'timeoutMs'), maxBytes: boundedOption(internalOptions, 'maxBytes'), maxKeys: boundedOption(internalOptions, 'maxKeys')};
  const diagnostics = [];
  for (const [index, url] of sources.entries()) {
    try { return await snapshot(await fetchSource(url, fetchImpl, limits), release, {type: 'fallback', url}); }
    catch (error) { diagnostics.push({index, code: error instanceof SourceError ? error.code : 'network-error', ...(error instanceof SourceError && error.status !== undefined ? {status: error.status} : {})}); }
  }
  throw new FallbackUnavailableError(diagnostics);
}
