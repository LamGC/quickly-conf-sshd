#!/usr/bin/env node
// This preparation tool only reads PUBLIC SSH keys and writes the exact bytes to sign offline.
// It never reads a signing private key, invokes gpg signing, or uploads anything.
import {readFile, writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {makeSignedDocument, parseSignedDocument, SIGNATURE_SEPARATOR, validateSignature} from '../cf-worker/src/signed-release.js';

export async function prepare(argv) {
  const options = {};
  for (let i = 0; i < argv.length; i++) {
    const key = argv[i];
    if (key === '--revoke') { options.revoke = true; continue; }
    if (!['--input', '--output', '--list-id', '--sequence', '--issued-at', '--expires-at', '--signature', '--bundle'].includes(key) || i + 1 >= argv.length || Object.hasOwn(options, key)) throw Error('Usage: node scripts/prepare-key-release.mjs --input PUBLIC_KEYS --output DOCUMENT --list-id ID --sequence N --issued-at EPOCH --expires-at EPOCH [--revoke]\nOr: --input DOCUMENT --signature SIGNATURE --bundle BUNDLE (pack only after offline signing).');
    options[key] = argv[++i];
  }
  if (options['--bundle']) {
    if (!options['--input'] || !options['--signature'] || Object.keys(options).some(key => !['--input', '--signature', '--bundle'].includes(key))) throw Error('Packing accepts only --input DOCUMENT --signature SIGNATURE --bundle BUNDLE.');
    const document = await readFile(options['--input'], 'utf8'), signature = await readFile(options['--signature'], 'utf8');
    await parseSignedDocument(document, {checkFreshness: false});
    validateSignature(signature);
    await writeFile(options['--bundle'], document + SIGNATURE_SEPARATOR + signature, {flag: 'wx', mode: 0o600});
    return 'Packed exact document and detached signature. Cryptographic verification is still required.';
  }
  if (!options['--input'] || !options['--output'] || !options['--list-id'] || options['--signature']) throw Error('Preparation requires --input, --output, --list-id, --sequence, --issued-at and --expires-at.');
  const numbers = {};
  for (const [key, field] of [['--sequence','sequence'], ['--issued-at','issuedAt'], ['--expires-at','expiresAt']]) {
    if (!/^(?:0|[1-9][0-9]{0,9})$/.test(options[key] ?? '')) throw Error(`${key} must be a canonical decimal integer.`);
    numbers[field] = Number(options[key]);
  }
  const document = await makeSignedDocument(await readFile(options['--input'], 'utf8'), {listId: options['--list-id'], ...numbers, revoke: Boolean(options.revoke)});
  await writeFile(options['--output'], document, {flag: 'wx', mode: 0o600});
  return 'Prepared comment-free bytes. Sign this exact file offline with an armored detached signature; never rewrite it afterward.';
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { console.log(await prepare(process.argv.slice(2))); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
