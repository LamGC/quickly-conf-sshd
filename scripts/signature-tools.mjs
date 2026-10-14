import {mkdtemp, writeFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {SIGNED_RELEASE_LIMITS, parseSignedBundle} from '../cf-worker/src/signed-release.js';

export function validatePublicCertificate(certificate) {
  if (typeof certificate !== 'string' || Buffer.byteLength(certificate) > SIGNED_RELEASE_LIMITS.publicKeyBytes || !/^-----BEGIN PGP PUBLIC KEY BLOCK-----\r?\n[\s\S]+\r?\n-----END PGP PUBLIC KEY BLOCK-----\r?\n?$/.test(certificate) || /[^\x09\x0a\x0d\x20-\x7e]/.test(certificate) || (certificate.match(/-----BEGIN /g) || []).length !== 1) throw Error('Expected one bounded ASCII-armored PUBLIC OpenPGP certificate, never private material.');
  return certificate;
}

/** Uses an ephemeral public-only keyring. Never loads the operator's keyring, signs, or retrieves keys. */
export async function checkSigningCertificate(certificate, fingerprint, signed = null) {
  validatePublicCertificate(certificate);
  if (typeof fingerprint !== 'string' || !/^[A-Fa-f0-9]{40}$/.test(fingerprint)) throw Error('A full primary signing fingerprint is required.');
  fingerprint = fingerprint.toUpperCase();
  const home = await mkdtemp(join(tmpdir(), 'conf-sshd-public-verify-'));
  const args = ['--no-options', '--homedir', home, '--batch', '--no-tty', '--no-autostart', '--no-auto-key-retrieve', '--auto-key-locate', 'clear'];
  const gpg = more => {try {return execFileSync('gpg', [...args, ...more], {encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 15000, maxBuffer: 4 * 1024 * 1024});} catch {throw Error('GPG public verification command failed.');}};
  try {
    const certPath = join(home, 'certificate.asc');
    await writeFile(certPath, certificate, {mode: 0o600});
    const packets = gpg(['--list-packets', certPath]);
    if (/:secret (?:sub )?key packet:/.test(packets)) throw Error('Secret key packets are not accepted.');
    const listing = gpg(['--with-colons', '--show-keys', certPath]);
    const records = listing.split('\n').map(line => line.split(':'));
    const primaries = records.filter(record => record[0] === 'pub');
    if (primaries.length !== 1 || records.some(record => record[0] === 'sec' || record[0] === 'ssb')) throw Error('The public certificate must contain exactly one primary identity.');
    if (['r', 'e', 'd'].includes(primaries[0][1]) || (primaries[0][6] && Number(primaries[0][6]) <= Math.floor(Date.now()/1000))) throw Error('Signing public certificate is expired, revoked, or disabled.');
    const primaryIndex = records.findIndex(record => record[0] === 'pub');
    const actual = records.slice(primaryIndex + 1).find(record => record[0] === 'fpr')?.[9];
    if (actual !== fingerprint) throw Error('Signing public certificate fingerprint mismatch.');
    if (!signed) return fingerprint;
    const parsed = await parseSignedBundle(signed, {checkFreshness: false});
    const keyring = join(home, 'public.gpg');
    gpg(['--output', keyring, '--dearmor', certPath]);
    const documentPath = join(home, 'document'), signaturePath = join(home, 'signature.asc');
    await writeFile(documentPath, parsed.document, {mode: 0o600});
    await writeFile(signaturePath, parsed.signature, {mode: 0o600});
    let status;
    try { status = gpg(['--no-default-keyring', '--keyring', keyring, '--status-fd', '1', '--verify', signaturePath, documentPath]); }
    catch { throw Error('Detached OpenPGP signature verification failed.'); }
    validatePayloadSignatureStatus(status, fingerprint);
    return fingerprint;
  } finally { await rm(home, {recursive: true, force: true}); }
}

export function validatePayloadSignatureStatus(output, fingerprint, now = Math.floor(Date.now() / 1000)) {
  const records = output.split(/\r?\n/).filter(line => line.startsWith('[GNUPG:] ')).map(line => line.slice(9).split(/ +/));
  const rejected = new Set(['BADSIG','ERRSIG','NO_PUBKEY','EXPSIG','EXPKEYSIG','REVKEYSIG','KEYEXPIRED','SIGEXPIRED','KEYREVOKED','FAILURE','ERROR','NODATA','BADARMOR']);
  if (records.some(record => rejected.has(record[0]))) throw Error('Detached signature is invalid, expired, revoked, or unverifiable.');
  const valid = records.filter(record => record[0] === 'VALIDSIG');
  if (valid.length !== 1) throw Error('Expected exactly one valid detached signature.');
  const [, signer, , timestamp, expires, version, , , hash, signatureClass, primary] = valid[0];
  if (valid[0].length !== 11 || !/^[A-Fa-f0-9]{40}$/.test(signer) || !/^[A-Fa-f0-9]{40}$/.test(primary || '') || version !== '4' || !['8','9','10'].includes(hash) || signatureClass !== '00') throw Error('Payload requires an OpenPGP v4 binary SHA-256/384/512 signature with a full primary fingerprint.');
  if (!/^\d+$/.test(timestamp) || !/^\d+$/.test(expires) || (Number(expires) !== 0 && Number(expires) <= now)) throw Error('Detached signature has expired or invalid timestamps.');
  if (primary.toUpperCase() !== fingerprint.toUpperCase()) throw Error('Detached signature primary identity is not pinned.');
  return {signerFingerprint:signer.toUpperCase(), primaryFingerprint:primary.toUpperCase()};
}
