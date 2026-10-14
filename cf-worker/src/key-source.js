import {parsePublishedSignedRelease, withoutKeyComments, SIGNED_BUNDLE_MAX_BYTES, SIGNATURE_SEPARATOR, SIGNED_RELEASE_LIMITS, validateListId} from './signed-release.js';

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
    super('No configured SSH key source returned a valid key release.');
    this.name = 'FallbackUnavailableError';
    this.code = 'KEY_SOURCES_UNAVAILABLE';
    // A mixed failure is still worth retrying if any upstream could not be retrieved.
    // This hint can only affect retry timing; it never makes a response trustworthy.
    this.failureKind = diagnostics.some(({code}) => ['network-error', 'timeout', 'http-error', 'redirect'].includes(code)) ? 'retrieval' : 'validation';
    // Keep diagnostics safe to log or return: no response content, URL secrets, or exception text.
    this.diagnostics = diagnostics.slice(0, KEY_SOURCE_LIMITS.sources).map(({index, code, status}) => ({index, code, ...(status === undefined ? {} : {status})}));
  }
}

/** Only an existing, deliberately blank primary file means revoke; comments do not. */
export function isExplicitEmptyKeyFile(input) {
  return typeof input === 'string' && /^[\t\r\n ]*$/.test(input);
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
  const payload = withoutKeyComments(keys).map(key => `${key.text}\n`).join('');
  const digest = hex(await sha256(encoder.encode(payload)));
  const text = `# conf-sshd-v1\n# revision ${revision}\n# key-count ${keys.length}\n# allow-empty ${allowEmpty ? 'yes' : 'no'}\n# sha256 ${digest}\n# end-metadata\n${payload}`;
  if (encoder.encode(text).length > KEY_SOURCE_LIMITS.maxBytes) throw new SourceError('too-large');
  return {sha256: digest, text};
}
async function snapshot(keys, release, source, signed = null) {
  if (!/^[0-9a-f]{40}$/.test(release.revision)) throw Error('Release revision must be a 40-character Git commit SHA.');
  keys = withoutKeyComments(keys);
  const allowEmpty = signed ? signed.metadata.revoke : release.allowEmpty;
  const bundle = signed ? {text: signed.document, sha256: hex(await sha256(encoder.encode(keys.map(key => key.text + '\n').join(''))))} : await makeKeyBundle(keys, release.revision, allowEmpty);
  return {keys, keysText: signed?.document ?? bundle.text, sha256: bundle.sha256, keyCount: keys.length, allowEmpty, source, revision: release.revision, keyRevision: signed ? signed.metadata.documentSha256 : bundle.sha256, fetchedAt: new Date().toISOString(), signedDocument: signed?.document ?? null, signature: signed?.signature ?? null, signatureAvailable: Boolean(signed?.signature), signedBundle: signed?.bundle ?? null, signedMetadata: signed?.metadata ?? null};
}

export function validateKeySource(value = {type: 'git'}) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error('keySource must be an object.');
  const allowed = value.type === 'git' ? ['type'] : ['type', 'id', 'ownerId', 'ownerLogin', 'file', 'signatureFile', 'bundleFile'];
  if (!['git', 'gist'].includes(value.type) || Object.keys(value).some(key => !allowed.includes(key))) throw Error('Invalid keySource configuration.');
  if (value.type === 'git') return {type: 'git'};
  if (typeof value.id !== 'string' || !/^[0-9a-f]{5,64}$/.test(value.id)) throw Error('Gist source requires a fixed lowercase hexadecimal ID.');
  if (!Number.isSafeInteger(value.ownerId) || value.ownerId < 1) throw Error('Gist source requires a positive numeric ownerId.');
  if (typeof value.ownerLogin !== 'string' || !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(value.ownerLogin)) throw Error('Gist source requires an ownerLogin display name.');
  const file = value.file ?? 'ssh.keys', signatureFile = value.signatureFile ?? `${file}.sig`, bundleFile = value.bundleFile ?? 'release.bundle';
  for (const name of [file, signatureFile, bundleFile]) if (typeof name !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(name)) throw Error('Gist filenames must be fixed plain filenames.');
  if (new Set([file, signatureFile, bundleFile]).size !== 3) throw Error('Gist key, signature, and bundle filenames must differ.');
  return {type: 'gist', id: value.id, ownerId: value.ownerId, ownerLogin: value.ownerLogin, file, signatureFile, bundleFile};
}

export function validateSignedReleaseConfig(value) {
  if (value === undefined || value === null) return null;
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !['listId', 'publicKeyFile', 'fingerprint'].includes(key))) throw Error('Invalid signedRelease configuration.');
  validateListId(value.listId);
  if (Boolean(value.publicKeyFile) !== Boolean(value.fingerprint)) throw Error('Build signature verification requires both publicKeyFile and fingerprint.');
  if (value.publicKeyFile !== undefined && (typeof value.publicKeyFile !== 'string' || !/^keys\/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value.publicKeyFile))) throw Error('Signing public key must be a fixed file inside keys/.');
  if (value.fingerprint !== undefined && (typeof value.fingerprint !== 'string' || !/^[A-Fa-f0-9]{40}$/.test(value.fingerprint))) throw Error('Signing fingerprint must be the complete 40-character primary fingerprint.');
  return {listId: value.listId, ...(value.publicKeyFile ? {publicKeyFile: value.publicKeyFile, fingerprint: value.fingerprint.toUpperCase()} : {})};
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
async function withDeadline(limits, operation, onTimeout) {
  const controller = new AbortController();
  let timer;
  const timeout = new Promise((resolve, reject) => {
    timer = setTimeout(() => { const recovery = onTimeout?.(); recovery === undefined ? reject(new SourceError('timeout')) : resolve(recovery); controller.abort(); }, limits.timeoutMs);
  });
  try { return await Promise.race([operation(controller.signal), timeout]); }
  finally { clearTimeout(timer); }
}
async function fetchText(url, fetchImpl, signal, maxBytes, github = false) {
  let response;
  try {
    response = await fetchImpl(url, {method: 'GET', redirect: 'manual', cache: 'no-store', headers: {'Accept': github ? 'application/vnd.github+json' : 'text/plain, application/octet-stream;q=0.9', 'Cache-Control': 'no-cache, no-store', 'Pragma': 'no-cache', ...(github ? {'User-Agent': 'conf-sshd-key-source', 'X-GitHub-Api-Version': '2022-11-28'} : {})}, signal});
    if (signal.aborted) throw new SourceError('timeout');
    if (response.redirected || (response.status >= 300 && response.status < 400)) throw new SourceError('redirect', response.status);
    if (response.status !== 200) throw new SourceError('http-error', response.status);
    return await readBody(response, signal, maxBytes);
  } finally {
    if (response?.body && !response.body.locked) void response.body.cancel().catch(() => {});
  }
}
async function parseSourceText(body, release, limits, options, signal, signature = null) {
  if (options.requireSigned || body.startsWith('# conf-sshd-signed-v1\n')) {
    try {
      const separator = body.indexOf(SIGNATURE_SEPARATOR);
      const document = separator < 0 ? body : body.slice(0, separator);
      if (separator >= 0) signature = body.slice(separator + SIGNATURE_SEPARATOR.length);
      const signed = await parsePublishedSignedRelease(document, signature, {listId: release.signedRelease?.listId, now: options.now, checkFreshness: Boolean(options.requireSigned), requireSigned: options.requireSigned, signal});
      if (signed.keys.length > limits.maxKeys) throw Error('Too many keys.');
      return {keys: signed.keys, signed};
    } catch { throw new SourceError('invalid-signed-release'); }
  }
  let keys;
  try { keys = await parsePublicKeys(body, {maxKeys: limits.maxKeys, signal}); } catch { throw new SourceError('invalid-keys'); }
  if (!keys.length) throw new SourceError('empty');
  return {keys, signed: null};
}
async function fetchSource(url, fetchImpl, limits, release, options) {
  let withoutSignature;
  return withDeadline(limits, async signal => {
    const body = await fetchText(url, fetchImpl, signal, limits.maxBytes === KEY_SOURCE_LIMITS.maxBytes ? SIGNED_BUNDLE_MAX_BYTES : limits.maxBytes);
    if (body.startsWith('# conf-sshd-signed-v1\n') && !body.includes(SIGNATURE_SEPARATOR)) {
      // A detached pair never combines different sources. A publication race remains a client signature failure.
      withoutSignature = await parseSourceText(body, release, limits, {...options, requireSigned: false}, signal);
      let signature = null;
      try { signature = await fetchText(url + '.sig', fetchImpl, signal, SIGNED_RELEASE_LIMITS.signatureBytes); } catch { /* OFF remains usable when the optional signature is unavailable. */ }
      return parseSourceText(body, release, limits, options, signal.aborted ? undefined : signal, signature);
    }
    return parseSourceText(body, release, limits, options, signal);
  }, () => options.requireSigned ? undefined : withoutSignature);
}
async function fetchGist(source, fetchImpl, limits, release, options) {
  return withDeadline(limits, async signal => {
    // Both requests, streamed bodies and parsing share one deadline; never follow an upstream raw_url.
    const get = async suffix => {
      const body = await fetchText(`https://api.github.com/gists/${source.id}${suffix}`, fetchImpl, signal, 2 * SIGNED_BUNDLE_MAX_BYTES, true);
      let data;
      try { data = JSON.parse(body); } catch { throw new SourceError('invalid-gist'); }
      if (!data || data.id !== source.id || data.owner?.id !== source.ownerId) throw new SourceError('gist-owner-mismatch');
      if (data.public !== true || data.truncated === true || !data.files || typeof data.files !== 'object' || Array.isArray(data.files)) throw new SourceError('invalid-gist');
      return data;
    };
    const latest = await get('');
    const gistRevision = latest.history?.[0]?.version;
    if (typeof gistRevision !== 'string' || !/^[0-9a-f]{40}$/.test(gistRevision)) throw new SourceError('invalid-gist-revision');
    const pinned = await get(`/${gistRevision}`);
    const readFile = filename => {
      const file = pinned.files[filename];
      if (!file || file.filename !== filename || file.truncated !== false || typeof file.content !== 'string' || (file.encoding !== undefined && file.encoding !== 'utf-8')) throw new SourceError('invalid-gist-file');
      const size = encoder.encode(file.content).length;
      const max = filename === source.bundleFile ? SIGNED_BUNDLE_MAX_BYTES : limits.maxBytes;
      if (!Number.isSafeInteger(file.size) || file.size !== size || size > max) throw new SourceError('too-large');
      return file;
    };
    const filename = Object.hasOwn(pinned.files, source.bundleFile) ? source.bundleFile : source.file;
    if (filename === source.bundleFile && Object.hasOwn(pinned.files, source.file)) {
      // A cleared split file must never be silently replaced by an older bundle,
      // or vice versa. Validate the clear before trusting it, then fail closed if
      // the other format conflicts or is unreadable. Both blank express one intent.
      const validEmpty = name => {
        if (!isExplicitEmptyKeyFile(pinned.files[name]?.content)) return false;
        try { return isExplicitEmptyKeyFile(readFile(name).content); } catch { return false; }
      };
      const splitEmpty = validEmpty(source.file), bundleEmpty = validEmpty(source.bundleFile);
      if (splitEmpty !== bundleEmpty) {
        throw new SourceError('ambiguous-empty-primary');
      }
    }
    const file = readFile(filename);
    const provenance = {type: 'gist', id: source.id, ownerId: source.ownerId, ownerLogin: source.ownerLogin, gistRevision, file: filename, url: `https://gist.github.com/${source.ownerLogin}/${source.id}/${gistRevision}`};
    const explicitEmpty = isExplicitEmptyKeyFile(file.content);
    if (explicitEmpty) {
      if (options.requireSigned) throw new SourceError('unsigned-revocation');
      return {keys: [], signed: null, explicitEmpty: true, source: provenance};
    }
    if (filename === source.bundleFile && (!file.content.startsWith('# conf-sshd-signed-v1\n') || !file.content.includes(SIGNATURE_SEPARATOR))) throw new SourceError('invalid-signed-release');
    // Optional signature is read only from this same immutable revision, never from latest/raw URLs.
    let signature = null;
    const signatureFile = pinned.files[source.signatureFile];
    if (signatureFile && signatureFile.filename === source.signatureFile && signatureFile.truncated === false && typeof signatureFile.content === 'string' && (signatureFile.encoding === undefined || signatureFile.encoding === 'utf-8') && Number.isSafeInteger(signatureFile.size) && signatureFile.size === encoder.encode(signatureFile.content).length && signatureFile.size <= SIGNED_RELEASE_LIMITS.signatureBytes) signature = signatureFile.content;
    const result = await parseSourceText(file.content, release, limits, options, signal, signature);
    return {...result, source: provenance};
  });
}

/** Only release-configured sources are accepted. requirePrimary disables fallback for deployment preflight.
 * Worker checks structure, never claims OpenPGP verification. */
export async function resolveKeys(release, fetchImpl = globalThis.fetch, internalOptions = {}) {
  if (!release || !Array.isArray(release.keys) || typeof release.allowEmpty !== 'boolean') throw new Error('Invalid deployed key release.');
  const keySource = validateKeySource(release.keySource);
  validateSignedReleaseConfig(release.signedRelease);
  if (internalOptions.requireSigned !== undefined && typeof internalOptions.requireSigned !== 'boolean') throw Error('requireSigned must be boolean.');
  if (internalOptions.requirePrimary !== undefined && typeof internalOptions.requirePrimary !== 'boolean') throw Error('requirePrimary must be boolean.');
  const limits = {timeoutMs: boundedOption(internalOptions, 'timeoutMs'), maxBytes: boundedOption(internalOptions, 'maxBytes'), maxKeys: boundedOption(internalOptions, 'maxKeys')};
  const sources = validateFallbackSources(release.fallbackSources);
  const diagnostics = [];
  if (keySource.type === 'git') {
    if (release.signedDocument || release.signedBundle) {
      // A malformed signed primary must never downgrade to different unsigned repository keys.
      try {
        const result = await parseSourceText(release.signedDocument || release.signedBundle, release, limits, internalOptions, undefined, release.signature ?? null);
        return await snapshot(result.keys, release, {type: result.signed.metadata.revoke ? 'explicit-empty' : 'repository'}, result.signed);
      } catch { diagnostics.push({index: -1, code: 'invalid-signed-release'}); }
    } else if (!internalOptions.requireSigned) {
      if (release.keys.length) return snapshot(release.keys, release, {type: 'repository'});
      // An explicit empty release means revoke. It must never be repopulated from a fallback.
      if (release.allowEmpty) return snapshot([], release, {type: 'explicit-empty'});
    }
    // An explicit unsigned empty primary cannot be replaced by signed fallback keys either.
    if (!release.signedDocument && !release.signedBundle && release.allowEmpty && !release.keys.length) throw new FallbackUnavailableError([{index: -1, code: 'unsigned-revocation'}]);
    if (internalOptions.requirePrimary && !diagnostics.length) diagnostics.push({index: -1, code: internalOptions.requireSigned && release.keys.length ? 'invalid-signed-release' : 'unconfigured-primary'});
  } else {
    try {
      const result = await fetchGist(keySource, fetchImpl, limits, release, internalOptions);
      return await snapshot(result.keys, result.explicitEmpty ? {...release, allowEmpty: true} : release, result.source, result.signed);
    } catch (error) {
      diagnostics.push(diagnostic(error, -1));
      if (error instanceof SourceError && ['unsigned-revocation', 'ambiguous-empty-primary'].includes(error.code)) throw new FallbackUnavailableError(diagnostics);
    }
  }
  if (internalOptions.requirePrimary) throw new FallbackUnavailableError(diagnostics);
  for (const [index, url] of sources.entries()) {
    try {
      const result = await fetchSource(url, fetchImpl, limits, release, internalOptions);
      return await snapshot(result.keys, release, {type: 'fallback', url}, result.signed);
    } catch (error) { diagnostics.push(diagnostic(error, index)); }
  }
  throw new FallbackUnavailableError(diagnostics);
}
function diagnostic(error, index) {
  return {index, code: error instanceof SourceError ? error.code : 'network-error', ...(error instanceof SourceError && error.status !== undefined ? {status: error.status} : {})};
}
