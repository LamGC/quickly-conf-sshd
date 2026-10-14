import {parsePublicKeys} from './key-source.js';

// Parsing is deliberately not OpenPGP verification. The enrolled client verifies these exact bytes.
export const SIGNED_RELEASE_LIMITS = Object.freeze({documentBytes: 1024 * 1024, signatureBytes: 64 * 1024, publicKeyBytes: 1024 * 1024, maxKeys: 1000, maxSequence: 2147483647, clockSkewSeconds: 300});
export const SIGNATURE_SEPARATOR = '# detached-signature\n';
export const SIGNED_BUNDLE_MAX_BYTES = SIGNED_RELEASE_LIMITS.documentBytes + SIGNED_RELEASE_LIMITS.signatureBytes + SIGNATURE_SEPARATOR.length;
const encoder = new TextEncoder();
const bytes = value => encoder.encode(value).length;
const listIdPattern = /^[A-Za-z0-9._-]{1,64}$/;
const decimal = /^(?:0|[1-9][0-9]{0,9})$/;

export function validateListId(value) {
  if (typeof value !== 'string' || value === '-' || !listIdPattern.test(value)) throw Error('Invalid signed release list ID.');
  return value;
}
export function withoutKeyComments(keys) {
  return keys.map((key, index) => ({...key, text: key.text.split(/[ \t]+/).slice(0, 2).join(' '), label: `Server key ${index + 1}`}));
}
export function validateSignature(signature) {
  if (typeof signature !== 'string' || bytes(signature) > SIGNED_RELEASE_LIMITS.signatureBytes || !signature.endsWith('\n') || /[^\x09\x0a\x20-\x7e]/.test(signature)) throw Error('Invalid or oversized detached signature.');
  const lines = signature.split('\n');
  if (lines.shift() !== '-----BEGIN PGP SIGNATURE-----' || lines.pop() !== '' || lines.pop() !== '-----END PGP SIGNATURE-----') throw Error('Expected one ASCII-armored PGP detached signature.');
  while (lines.length && /^[A-Za-z][A-Za-z0-9-]*: [\x20-\x7e]*$/.test(lines[0])) lines.shift();
  if (lines.shift() !== '') throw Error('Invalid PGP armor header.');
  if (lines.length && /^=[A-Za-z0-9+/]{4}$/.test(lines.at(-1))) lines.pop();
  if (!lines.length || lines.some((line, i) => !/^[A-Za-z0-9+/]{1,76}={0,2}$/.test(line) || (i !== lines.length - 1 && line.includes('=')))) throw Error('Invalid PGP armor body.');
  const payload = lines.join('');
  try { if (!atob(payload).length) throw Error(); } catch { throw Error('Invalid PGP armor encoding.'); }
  return signature;
}

export async function parseSignedDocument(document, {listId, now = Math.floor(Date.now() / 1000), checkFreshness = true, signal} = {}) {
  if (typeof document !== 'string' || bytes(document) > SIGNED_RELEASE_LIMITS.documentBytes || !document.endsWith('\n')) throw Error('Invalid or oversized signed document.');
  const match = /^# conf-sshd-signed-v1\n# list-id ([A-Za-z0-9._-]{1,64})\n# sequence ([1-9][0-9]{0,9})\n# issued-at (0|[1-9][0-9]{0,9})\n# expires-at (0|[1-9][0-9]{0,9})\n# revoke (yes|no)\n# key-count (0|[1-9][0-9]{0,3})\n# end-metadata\n([\s\S]*)$/.exec(document);
  if (!match) throw Error('Invalid signed document metadata.');
  const [, parsedListId, sequenceText, issuedText, expiresText, revokeText, countText, body] = match;
  validateListId(parsedListId);
  const sequence = Number(sequenceText), issuedAt = Number(issuedText), expiresAt = Number(expiresText), keyCount = Number(countText), revoke = revokeText === 'yes';
  if (sequence > SIGNED_RELEASE_LIMITS.maxSequence || keyCount > SIGNED_RELEASE_LIMITS.maxKeys || expiresAt <= issuedAt || revoke !== (keyCount === 0)) throw Error('Inconsistent signed release policy.');
  if (listId !== undefined && parsedListId !== validateListId(listId)) throw Error('Signed release list ID mismatch.');
  if (checkFreshness && (!Number.isSafeInteger(now) || now < 0 || issuedAt > now + SIGNED_RELEASE_LIMITS.clockSkewSeconds || expiresAt <= now)) throw Error('Signed release is expired or not yet valid.');
  const keys = withoutKeyComments(await parsePublicKeys(body, {signal}));
  // Never normalize, strip comments, add padding, or alter a signed byte during verification/serving.
  if (keys.length !== keyCount || keys.map(key => key.text + '\n').join('') !== body) throw Error('Signed key body must be canonical and match its key count.');
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(document)));
  const documentSha256 = Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('');
  return {document, keys, metadata: {listId: parsedListId, sequence, issuedAt, expiresAt, revoke, keyCount, documentSha256}};
}

export async function parseSignedBundle(bundle, options = {}) {
  if (typeof bundle !== 'string' || bytes(bundle) > SIGNED_BUNDLE_MAX_BYTES) throw Error('Invalid or oversized signed bundle.');
  const separator = bundle.indexOf(SIGNATURE_SEPARATOR);
  if (separator < 0 || bundle.indexOf(SIGNATURE_SEPARATOR, separator + SIGNATURE_SEPARATOR.length) !== -1) throw Error('Signed bundle must contain exactly one detached-signature separator.');
  const document = bundle.slice(0, separator), signature = bundle.slice(separator + SIGNATURE_SEPARATOR.length);
  validateSignature(signature);
  return {...await parseSignedDocument(document, options), signature, bundle};
}

/** Prepare public bytes for an OFFLINE signer. This function never handles a private key. */
export async function makeSignedDocument(input, {listId, sequence, issuedAt, expiresAt, revoke = false}) {
  validateListId(listId);
  for (const [name, value] of Object.entries({sequence, issuedAt, expiresAt})) if (!Number.isSafeInteger(value) || !decimal.test(String(value))) throw Error(`Invalid ${name}.`);
  if (typeof revoke !== 'boolean') throw Error('revoke must be an explicit boolean.');
  const keys = withoutKeyComments(await parsePublicKeys(input));
  const document = `# conf-sshd-signed-v1\n# list-id ${listId}\n# sequence ${sequence}\n# issued-at ${issuedAt}\n# expires-at ${expiresAt}\n# revoke ${revoke ? 'yes' : 'no'}\n# key-count ${keys.length}\n# end-metadata\n${keys.map(key => key.text + '\n').join('')}`;
  await parseSignedDocument(document, {checkFreshness: false});
  return document;
}

/** A public endpoint may expose a document without a usable signature; OFF clients do not depend on it. */
export async function parsePublishedSignedRelease(document, signature = null, options = {}) {
  const parsed = await parseSignedDocument(document, options);
  let acceptedSignature = null;
  try { if (signature !== null) acceptedSignature = validateSignature(signature); }
  catch { if (options.requireSigned) throw Error('Invalid detached signature.'); }
  if (options.requireSigned && acceptedSignature === null) throw Error('Missing detached signature.');
  return {...parsed, signature: acceptedSignature, bundle: acceptedSignature === null ? null : document + SIGNATURE_SEPARATOR + acceptedSignature};
}
