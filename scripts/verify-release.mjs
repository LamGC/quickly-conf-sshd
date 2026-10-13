import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {parsePublicKeys} from '../cf-worker/src/key-source.js';
import {parseSignedDocument, SIGNATURE_SEPARATOR, SIGNED_RELEASE_LIMITS, withoutKeyComments, validateSignature} from '../cf-worker/src/signed-release.js';
import {checkSigningCertificate} from './signature-tools.mjs';
const hash = text => createHash('sha256').update(text).digest('hex');
const root = new URL('../', import.meta.url);

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

export async function verifyRemote(manifest, fetchImpl = fetch) {
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
  } else {
    const match = /^# conf-sshd-v1\n# revision ([0-9a-f]{40})\n# key-count (0|[1-9][0-9]*)\n# allow-empty (yes|no)\n# sha256 ([0-9a-f]{64})\n# end-metadata\n([\s\S]*)$/.exec(document);
    if (!match || match[1] !== manifest.revision) throw Error('Remote key manifest invalid.');
    const [, , countText, empty, digest, payload] = match;
    if (hash(payload) !== digest) throw Error('Remote key body does not match its response digest.');
    const keys = await parsePublicKeys(payload);
    count = keys.length; payloadHash = digest;
    if (keys.length !== Number(countText) || (!keys.length && (!manifest.allowEmpty || empty !== 'yes')) || withoutKeyComments(keys).map(key => key.text + '\n').join('') !== payload) throw Error('Remote key count/empty/canonical policy invalid.');
    if (manifest.clientDefaults?.gpgVerification === 'on') throw Error('Verification-enabled clients require a signed-format document.');
  }
  if (!dynamic && payloadHash !== manifest.sha256) throw Error('Remote repository payload differs from this build.');
  // Dynamic sources may change between requests; build revision is independent of key sequence/digest.
  return `Remote code release checked: ${metadata.revision}; key payload ${payloadHash} (${count} keys).${cryptoNote}`;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const manifest = JSON.parse(await readFile(new URL('cf-worker/generated/manifest.json', root), 'utf8'));
  if (manifest.testFixture) throw Error('Refusing to deploy a test-fixture build. Run the production build with real server public keys.');
  if (!process.argv.includes('--remote')) console.log(`Production release checked: ${manifest.revision}`);
  else console.log(await verifyRemote(manifest));
}
