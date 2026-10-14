// This verifier and the workflow are trusted repository code, not an immutable
// security boundary. Protect changes to both; trusted keys/pins live in Actions
// variables outside this commit. No npm packages or repository imports are used.
import {spawnSync} from 'node:child_process';
import {mkdtemp, writeFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

export function enabledFlag(value, name = 'REQUIRE_GPG_SIGNATURE') {
  if (value === undefined || value === '' || value === 'false') return false;
  if (value === 'true') return true;
  throw Error(`${name} must be unset, false, or exactly true.`);
}

export function parseFingerprints(value) {
  const values = typeof value === 'string' ? value.trim().split(/[\s,]+/).filter(Boolean) : [];
  if (!values.length || values.some(value => !/^[0-9a-fA-F]{40}$/.test(value))) {
    throw Error('GPG_ALLOWED_PRIMARY_FINGERPRINTS must contain full 40-hex OpenPGP v4 primary fingerprints.');
  }
  return new Set(values.map(value => value.toUpperCase()));
}

export function verifySignatureStatus(output, allowed, now = Math.floor(Date.now() / 1000)) {
  const records = output.split(/\r?\n/).filter(line => line.startsWith('[GNUPG:] ')).map(line => line.slice(9).split(/ +/));
  const rejected = new Set(['BADSIG','ERRSIG','NO_PUBKEY','EXPSIG','EXPKEYSIG','REVKEYSIG','KEYEXPIRED','SIGEXPIRED','KEYREVOKED','FAILURE','ERROR','NODATA','BADARMOR']);
  if (records.some(record => rejected.has(record[0]))) throw Error('Commit signature is invalid, expired, revoked, or unverifiable.');
  const valid = records.filter(record => record[0] === 'VALIDSIG');
  if (valid.length !== 1) throw Error('Expected exactly one valid OpenPGP commit signature.');
  const [, signer, , timestamp, expires, version, , , hash, signatureClass, primary] = valid[0];
  if (valid[0].length !== 11 || !/^[A-Fa-f0-9]{40}$/.test(signer) || !/^[A-Fa-f0-9]{40}$/.test(primary || '') || version !== '4' || !['8','9','10'].includes(hash) || signatureClass !== '00') {
    throw Error('Commit requires an OpenPGP v4 SHA-256/384/512 signature with full primary fingerprint.');
  }
  if (!/^\d+$/.test(timestamp) || !/^\d+$/.test(expires) || (Number(expires) !== 0 && Number(expires) <= now)) throw Error('Commit signature has expired or invalid timestamps.');
  if (!allowed.has(primary.toUpperCase())) throw Error('Commit signer primary fingerprint is not pinned.');
  return {signerFingerprint:signer.toUpperCase(), primaryFingerprint:primary.toUpperCase()};
}

function run(command, args, {cwd, env, input} = {}) {
  const result = spawnSync(command, args, {cwd, env, input, encoding:'utf8', timeout:30_000, maxBuffer:4 * 1024 * 1024});
  // Never relay GPG key text/UIDs or arbitrary subprocess errors into CI logs.
  if (result.error || result.status !== 0 || result.signal) throw Error(`${command === 'git' ? 'Git' : 'GPG'} verification command failed.`);
  return result;
}

export async function verifyCommitSignature({env = process.env, directory = process.cwd()} = {}) {
  const required = enabledFlag(env.REQUIRE_GPG_SIGNATURE);
  const revision = env.GITHUB_SHA;
  if (!/^[0-9a-f]{40}$/.test(revision || '')) throw Error('GITHUB_SHA must be the exact 40-hex commit SHA.');
  const cleanEnv = {...env, GIT_CONFIG_NOSYSTEM:'1', GIT_CONFIG_GLOBAL:'/dev/null', GIT_NO_REPLACE_OBJECTS:'1'};
  const head = run('git', ['-c','core.fsmonitor=false','rev-parse','--verify','HEAD'], {cwd:directory,env:cleanEnv}).stdout.trim();
  if (head !== revision) throw Error('Checked-out HEAD does not match GITHUB_SHA.');
  if (!required) return {required:false,revision};
  const allowed = parseFingerprints(env.GPG_ALLOWED_PRIMARY_FINGERPRINTS);
  const publicKeys = env.GPG_PUBLIC_KEYS;
  if (typeof publicKeys !== 'string' || !publicKeys.includes('-----BEGIN PGP PUBLIC KEY BLOCK-----') || publicKeys.includes('PRIVATE KEY')) throw Error('GPG_PUBLIC_KEYS must contain externally configured armored public keys only.');
  const home = await mkdtemp(join(tmpdir(), 'conf-sshd-gpg-'));
  try {
    const gpgEnv = {...cleanEnv, GNUPGHOME:home};
    const options = ['--no-options','--homedir',home,'--batch','--no-tty','--no-autostart','--no-auto-key-retrieve','--auto-key-locate','clear'];
    // Decode into an isolated legacy public keyring without importing keys or
    // contacting gpg-agent. This also avoids starting secret-key services in CI.
    const listing = run('gpg', [...options,'--with-colons','--show-keys'], {env:gpgEnv,input:publicKeys}).stdout;
    if (!/^pub:/m.test(listing) || /^(?:sec|ssb):/m.test(listing)) throw Error('Only public verification keys are allowed.');
    run('gpg', [...options,'--output',join(home,'public.gpg'),'--dearmor'], {env:gpgEnv,input:publicKeys});
    const wrapper = join(home,'verify-gpg');
    await writeFile(wrapper, '#!/bin/sh\nexec gpg --no-options --homedir "$GNUPGHOME" --no-default-keyring --keyring "$GNUPGHOME/public.gpg" --batch --no-tty --no-autostart --no-auto-key-retrieve --auto-key-locate clear "$@"\n', {mode:0o700});
    const result = run('git', ['-c','core.fsmonitor=false','-c','gpg.format=openpgp','-c',`gpg.program=${wrapper}`,'-c',`gpg.openpgp.program=${wrapper}`,'verify-commit','--raw',revision], {cwd:directory,env:gpgEnv});
    return {required:true,revision,...verifySignatureStatus(result.stderr,allowed)};
  } finally {
    await rm(home,{recursive:true,force:true});
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 2) throw Error('Usage: node scripts/verify-commit-signature.mjs');
    const result = await verifyCommitSignature();
    console.log(result.required ? `Verified commit ${result.revision} with pinned primary ${result.primaryFingerprint}.` : `GPG commit gate disabled; checked exact commit ${result.revision}.`);
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
