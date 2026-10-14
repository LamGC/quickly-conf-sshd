import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {parsePublicKeys, resolveKeys, validateKeySource} from '../cf-worker/src/key-source.js';
import {parseSignedDocument, SIGNATURE_SEPARATOR, SIGNED_RELEASE_LIMITS, withoutKeyComments, validateSignature} from '../cf-worker/src/signed-release.js';
import {checkSigningCertificate} from './signature-tools.mjs';
const hash = text => createHash('sha256').update(text).digest('hex');
const root = new URL('../', import.meta.url);

/** Deployment checks the primary itself; a healthy fallback cannot hide an unconfigured primary. */
export async function verifyProduction(release, fetchImpl = fetch, {now, timeoutMs} = {}) {
  if (!release || release.testFixture) throw Error('Refusing to deploy a test-fixture or missing build. Run the production build with real server public keys.');
  if (!/^[0-9a-f]{40}$/.test(release.revision)) throw Error('Production release revision is invalid.');
  const keySource = validateKeySource(release.keySource);
  if (keySource.type === 'git' && !['keys/authorized_keys', 'keys/ssh.keys', 'keys/release.bundle'].includes(release.primaryFile)) throw Error('Production Git release has no configured primary file. Rebuild with an existing key file.');
  if (keySource.type === 'git' && !release.signedDocument && !release.signedBundle && !release.keys?.length && release.explicitEmpty !== true) throw Error('Production Git revocation lacks an explicitly empty primary file. Rebuild with an existing empty key file.');
  const requireSigned = release.clientDefaults?.gpgVerification === 'on';
  const snapshot = await resolveKeys(release, fetchImpl, {requirePrimary: true, requireSigned, ...(now === undefined ? {} : {now}), ...(timeoutMs === undefined ? {} : {timeoutMs})});
  if (requireSigned && snapshot.signedMetadata?.listId !== release.clientDefaults.listId) throw Error('Client default list ID differs from the primary signed document.');
  if (requireSigned && release.signedRelease?.fingerprint && release.clientDefaults.pinMode === 'primary' && release.clientDefaults.fingerprint !== release.signedRelease.fingerprint) throw Error('Client primary fingerprint differs from the configured signing certificate.');
  if (snapshot.signedDocument && release.signedRelease?.publicKeyFile) {
    if (!snapshot.signedBundle) throw Error('Configured build signature verification requires a valid detached signature.');
    await checkSigningCertificate(release.publicCertificate, release.signedRelease.fingerprint, snapshot.signedBundle);
  }
  const cryptoNote = snapshot.signedDocument && !release.signedRelease?.publicKeyFile ? ' OpenPGP not checked: no build verification certificate configured.' : '';
  return `Production primary checked: ${release.revision}; ${snapshot.keyCount} key(s) from ${snapshot.source.type}.${cryptoNote}`;
}

async function remoteText(url, maxBytes, {allowMissing = false, fetchImpl = fetch} = {}) {
  const signal = AbortSignal.timeout(20000);
  const response = await fetchImpl(url, {cache: 'no-store', redirect: 'error', signal});
  if (allowMissing && response.status === 404) { await response.body?.cancel(); return null; }
  if (response.status !== 200) { await response.body?.cancel(); throw Error(`Endpoint returned HTTP ${response.status}.`); }
  const reader = response.body?.getReader();
  if (!reader) return '';
  let bytes = new Uint8Array(Math.min(16384,maxBytes)), size = 0;
  try {
    while (true) {
      const {value, done} = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) throw Error('Remote response exceeds its size limit.');
      if (size > bytes.length) { const grown = new Uint8Array(Math.min(maxBytes, Math.max(size, bytes.length * 2))); grown.set(bytes); bytes = grown; }
      bytes.set(value,size-value.byteLength);
    }
    return new TextDecoder('utf-8', {fatal: true}).decode(bytes.subarray(0,size));
  } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
}

export async function verifyRemote(manifest, fetchImpl = fetch, {now} = {}) {
  const read = (path, maxBytes, allowMissing = false) => remoteText(manifest.baseUrl + path, maxBytes, {allowMissing, fetchImpl});
  const metadata = JSON.parse(await read('/release.json', 64 * 1024));
  if (metadata.revision !== manifest.revision || metadata.testFixture) throw Error('Remote release does not match this build.');
  if (!/^[0-9a-f]{64}$/.test(metadata.sha256)) throw Error('Remote key digest is invalid.');
  const dynamic = manifest.needsSource || manifest.needsFallback || manifest.keySource?.type === 'gist';
  if (dynamic) {
    const source = metadata.source;
    const acceptedFallback = source?.type === 'fallback' && manifest.fallbackSources.includes(source.url);
    const acceptedGist = manifest.keySource?.type === 'gist' && source?.type === 'gist' && source.id === manifest.keySource.id && source.ownerId === manifest.keySource.ownerId && /^[0-9a-f]{40}$/.test(source.gistRevision);
    if (!acceptedFallback && !acceptedGist) throw Error('Unexpected effective dynamic source.');
  } else if (metadata.sha256 !== manifest.sha256) throw Error('Remote repository keys differ from this build.');
  const document = await read('/ssh.keys', SIGNED_RELEASE_LIMITS.documentBytes);
  let count, payloadHash, cryptoNote = "";
  if (document.startsWith('# conf-sshd-signed-v1\n')) {
    const parsed = await parseSignedDocument(document, {listId: manifest.signedRelease?.listId, checkFreshness: false});
    count = parsed.keys.length;
    payloadHash = hash(parsed.keys.map(key => key.text + '\n').join(''));
    if (!dynamic && parsed.metadata.documentSha256 !== manifest.signedMetadata?.documentSha256) throw Error('Remote signed document differs from this build.');
    // Each detached signature must validate THIS exact document; an update race fails safely and can be retried.
    const signature = await read('/ssh.keys.sig', SIGNED_RELEASE_LIMITS.signatureBytes, true);
    if (manifest.signedRelease?.publicKeyFile) {
      if (signature === null) throw Error('Remote signature is missing.');
      const certificate = await read('/public-key.gpg', SIGNED_RELEASE_LIMITS.publicKeyBytes);
      await checkSigningCertificate(certificate, manifest.signedRelease.fingerprint, document + SIGNATURE_SEPARATOR + signature);
    } else {
      if ((manifest.signatureAvailable || manifest.clientDefaults?.gpgVerification === 'on') && signature === null) throw Error('Expected remote signature is missing.');
      if (signature !== null) validateSignature(signature);
      cryptoNote = ' OpenPGP not checked: no build verification certificate configured.';
    }
    if (manifest.clientDefaults?.gpgVerification === 'on') await parseSignedDocument(document, {listId: manifest.clientDefaults.listId, ...(now === undefined ? {} : {now})});
  } else {
    const match = /^# conf-sshd-v1\n# revision ([0-9a-f]{40})\n# key-count (0|[1-9][0-9]*)\n# allow-empty (yes|no)\n# sha256 ([0-9a-f]{64})\n# end-metadata\n([\s\S]*)$/.exec(document);
    if (!match || match[1] !== manifest.revision) throw Error('Remote key manifest invalid.');
    const [, , countText, empty, digest, payload] = match;
    if (hash(payload) !== digest) throw Error('Remote key body does not match its response digest.');
    const keys = await parsePublicKeys(payload);
    count = keys.length; payloadHash = digest;
    // A pinned Gist may be intentionally cleared after this code build, without changing allowEmpty.
    const gistRevocation = manifest.keySource?.type === 'gist' && metadata.source?.type === 'gist' && metadata.allowEmpty === true && metadata.keyCount === 0;
    if (keys.length !== Number(countText) || (!keys.length && ((!manifest.allowEmpty && !gistRevocation) || empty !== 'yes')) || withoutKeyComments(keys).map(key => key.text + '\n').join('') !== payload) throw Error('Remote key count/empty/canonical policy invalid.');
    if (manifest.clientDefaults?.gpgVerification === 'on') throw Error('Verification-enabled clients require a signed-format document.');
  }
  if (!dynamic && payloadHash !== manifest.sha256) throw Error('Remote repository payload differs from this build.');
  // Dynamic sources may change between requests; build revision is independent of key sequence/digest.
  return `Remote code release checked: ${metadata.revision}; key payload ${payloadHash} (${count} keys).${cryptoNote}`;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.some(arg => arg !== '--remote') || args.length > 1) throw Error('Usage: node scripts/verify-release.mjs [--remote]');
  if (args.includes('--remote')) {
    const manifest = JSON.parse(await readFile(new URL('cf-worker/generated/manifest.json', root), 'utf8'));
    if (manifest.testFixture) throw Error('Refusing to verify a test-fixture deployment.');
    console.log(await verifyRemote(manifest));
  } else {
    const {default: release} = await import(new URL('cf-worker/generated/release.js', root));
    console.log(await verifyProduction(release));
  }
}
