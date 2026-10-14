import { readFile, writeFile, mkdir, rm, mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';

export const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const digest = data => createHash('sha256').update(data).digest('hex');
import { escapeHTML, commandsFor, renderCommands, renderPage } from '../cf-worker/src/view.js';
export { escapeHTML, commandsFor, renderCommands };
import { validateFallbackSources, parsePublicKeys, validateKeySource, validateSignedReleaseConfig, isExplicitEmptyKeyFile } from '../cf-worker/src/key-source.js';
import {withoutKeyComments, parsePublishedSignedRelease, SIGNATURE_SEPARATOR} from '../cf-worker/src/signed-release.js';
import {checkSigningCertificate, validatePublicCertificate} from './signature-tools.mjs';


export function validateConfig(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) throw Error('Deployment configuration must be an object.');
  for (const key of Object.keys(config)) if (!['baseUrl','repositoryUrl','defaultCron','allowEmpty','fallbackSources','keySource','signedRelease','clientDefaults'].includes(key)) throw Error(`Unknown configuration: ${key}`);
  if (typeof config.baseUrl !== 'string' || !/^https:\/\/[a-zA-Z0-9.-]+(?::[0-9]+)?$/.test(config.baseUrl)) throw Error('baseUrl must be an HTTPS origin without paths, credentials, or shell metacharacters.');
  const url = new URL(config.baseUrl);
  if (url.origin !== config.baseUrl || !url.hostname.includes('.') || url.hostname.includes('..')) throw Error('baseUrl must be a canonical HTTPS origin.');
  if (typeof config.repositoryUrl !== 'string' || !/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(config.repositoryUrl)) throw Error('repositoryUrl must identify a GitHub repository.');
  if (typeof config.allowEmpty !== 'boolean') throw Error('allowEmpty must be an explicit boolean.');
  validateFallbackSources(Object.hasOwn(config, 'fallbackSources') ? config.fallbackSources : []);
  validateKeySource(config.keySource);
  validateSignedReleaseConfig(config.signedRelease);
  validateClientDefaults(config.clientDefaults);
  const cron = config.defaultCron;
  if (typeof cron !== 'string' || cron.trim() !== cron || !/^[0-9*,/ -]+$/.test(cron) || cron.split(/ +/).length !== 5) throw Error('defaultCron must contain five numeric cron fields.');
  const bounds = [[0,59],[0,23],[1,31],[1,12],[0,7]];
  cron.split(/ +/).forEach((field, i) => {
    for (const part of field.split(',')) {
      const match = /^(\*|\d+(?:-\d+)?)(?:\/(\d+))?$/.exec(part);
      if (!match || (match[2] && (+match[2] < 1 || +match[2] > bounds[i][1] + 1))) throw Error('Invalid cron expression.');
      if (match[1] !== '*') {
        const [a,b = a] = match[1].split('-').map(Number);
        if (a < bounds[i][0] || b > bounds[i][1] || a > b) throw Error('Cron value outside its field range.');
      }
    }
  });
  return config;
}

export function validateClientDefaults(value = {}) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !['gpgVerification', 'fingerprint', 'pinMode', 'listId', 'email'].includes(key))) throw Error('Invalid clientDefaults configuration.');
  const result = {gpgVerification: value.gpgVerification ?? 'off', fingerprint: value.fingerprint ?? '', pinMode: value.pinMode ?? 'primary', listId: value.listId ?? '', email: value.email ?? ''};
  if (!['off', 'on'].includes(result.gpgVerification) || !['primary', 'subkey'].includes(result.pinMode)) throw Error('Invalid client verification defaults.');
  if (typeof result.fingerprint !== 'string' || (result.fingerprint !== '' && !/^[A-Fa-f0-9]{40}$/.test(result.fingerprint))) throw Error('Client fingerprint must be empty or a full 40-character fingerprint.');
  if (typeof result.listId !== 'string' || result.listId === '-' || (result.listId !== '' && !/^[A-Za-z0-9._-]{1,64}$/.test(result.listId))) throw Error('Invalid client list ID.');
  if (result.gpgVerification === 'on' && (!result.fingerprint || !result.listId)) throw Error('Enabled verification defaults require a full fingerprint and list ID.');
  if (typeof result.email !== 'string' || (result.email !== '' && (!/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$/.test(result.email) || result.email.length > 254))) throw Error('Client email must be empty or a safe public email address.');
  result.fingerprint = result.fingerprint.toUpperCase();
  return result;
}

export async function parseKeys(input) {
  // Use the exact runtime parser, then additionally verify against the build's OpenSSH tools.
  const keys = await parsePublicKeys(input);
  const directory = await mkdtemp(join(tmpdir(), 'conf-sshd-key-check-'));
  try {
    for (const key of keys) {
      const file = join(directory, 'key.pub');
      await writeFile(file, key.text + '\n', {mode:0o600});
      try { execFileSync('ssh-keygen',['-l','-E','sha256','-f',file],{stdio:['ignore','pipe','pipe']}); }
      catch { throw Error('ssh-keygen rejected a public key (OpenSSH client tools are required).'); }
    }
  } finally { await rm(directory,{recursive:true,force:true}); }
  return keys;
}

export function makeKeysText(keys, revision, allowEmpty) {
  if (!/^[0-9a-f]{40}$/.test(revision)) throw Error('Release revision must be a 40-character Git commit SHA.');
  if (typeof allowEmpty !== 'boolean') throw Error('allowEmpty must be an explicit boolean.');
  if (!keys.length && !allowEmpty) throw Error('No server public keys configured. Add keys/authorized_keys, or explicitly allow an empty revocation release.');
  const payload = withoutKeyComments(keys).map(key => key.text + '\n').join('');
  const sha256 = digest(payload);
  const text = `# conf-sshd-v1\n# revision ${revision}\n# key-count ${keys.length}\n# allow-empty ${allowEmpty ? 'yes' : 'no'}\n# sha256 ${sha256}\n# end-metadata\n${payload}`;
  if (Buffer.byteLength(text) > 1024 * 1024) throw Error('Serialized key release exceeds client response limit.');
  return {sha256,text};
}


export async function build({directory = root, outDirectory = join(directory,'cf-worker'), testFixture = false, revision, publishedAt} = {}) {
  const config = validateConfig(JSON.parse(await readFile(join(directory,'deployment.json'),'utf8')));
  const optional = async path => { try { return await readFile(join(directory, path), 'utf8'); } catch (error) { if (error.code === 'ENOENT') return null; throw error; } };
  let input = testFixture ? await readFile(join(directory, 'tests/fixtures/keys.pub'), 'utf8') : config.keySource?.type === 'gist' ? null : await optional('keys/authorized_keys');
  let keys = [];
  revision ||= process.env.GITHUB_SHA || execFileSync('git',['rev-parse','HEAD'],{cwd:directory,encoding:'utf8'}).trim();
  if (!/^[0-9a-f]{40}$/.test(revision)) throw Error('Release revision must be a 40-character Git commit SHA.');
  publishedAt ||= new Date().toISOString();
  const fallbackSources = validateFallbackSources(config.fallbackSources ?? []);
  const keySource = validateKeySource(config.keySource), signedRelease = validateSignedReleaseConfig(config.signedRelease);
  let signed = null, publicCertificate = null, primaryFile = null;
  if (keySource.type === 'git' && !testFixture) {
    const documentFile = await optional('keys/ssh.keys'), bundleFile = await optional('keys/release.bundle');
    if (documentFile !== null && bundleFile !== null) throw Error('Use keys/ssh.keys plus its optional signature OR keys/release.bundle, not both.');
    if (documentFile !== null || bundleFile !== null) {
      // Do not let a leftover signed artifact silently override an explicitly cleared raw file.
      if (isExplicitEmptyKeyFile(input)) throw Error('Ambiguous Git revocation: empty keys/authorized_keys conflicts with a signed publishing file. Keep only the intended publishing form.');
      const rawHasContent = input !== null && input.split(/\r?\n/).some(line => {const text = line.replace(/^[ \t]+|[ \t]+$/g, ''); return text !== '' && !text.startsWith('#');});
      if (isExplicitEmptyKeyFile(documentFile ?? bundleFile) && rawHasContent) throw Error('Ambiguous Git revocation: empty signed publishing file conflicts with nonempty keys/authorized_keys. Keep only the intended publishing form.');
      primaryFile = documentFile !== null ? 'keys/ssh.keys' : 'keys/release.bundle';
      input = documentFile ?? bundleFile;
      if (!isExplicitEmptyKeyFile(input)) {
        const separator = bundleFile?.indexOf(SIGNATURE_SEPARATOR) ?? -1;
        if (bundleFile !== null && separator < 0) throw Error('release.bundle lacks its detached-signature separator.');
        const document = documentFile ?? bundleFile.slice(0, separator);
        const signature = documentFile !== null ? await optional('keys/ssh.keys.sig') : bundleFile.slice(separator + SIGNATURE_SEPARATOR.length);
        signed = await parsePublishedSignedRelease(document, signature, {listId: signedRelease?.listId, checkFreshness: false});
        keys = signed.keys;
      }
    } else primaryFile = 'keys/authorized_keys';
    if (input === null) throw Error(`No server public keys configured: ${primaryFile} is missing. Keep an existing empty file for an explicit revocation.`);
  }
  // A blank file may use lone CR line endings; retain its byte count for parser limits.
  if (!signed) keys = withoutKeyComments(await parseKeys(isExplicitEmptyKeyFile(input) ? input.replace(/\r/g, '\n') : input ?? ''));
  const explicitEmpty = !testFixture && keySource.type === 'git' && isExplicitEmptyKeyFile(input);
  if (!testFixture && keySource.type === 'git' && !signed && !keys.length && !explicitEmpty) throw Error('No server public keys configured: a comments-only placeholder is not an explicit empty revocation.');
  if (signedRelease?.publicKeyFile) {
    publicCertificate = validatePublicCertificate(await readFile(join(directory, signedRelease.publicKeyFile), 'utf8'));
    if (signed && !signed.bundle) throw Error('Configured build signature verification requires a valid detached signature.');
    await checkSigningCertificate(publicCertificate, signedRelease.fingerprint, signed?.bundle);
  }
  const allowEmpty = signed ? signed.metadata.revoke : explicitEmpty || config.allowEmpty;
  const needsFallback = keySource.type === 'git' && keys.length === 0 && !allowEmpty && fallbackSources.length > 0;
  const needsSource = keySource.type === 'gist' || needsFallback;
  if (keySource.type === 'gist') keys = [];
  const bundle = needsSource ? {sha256:null,text:null} : signed ? {sha256:digest(keys.map(key=>key.text+'\n').join('')),text:signed.document} : makeKeysText(keys,revision,allowEmpty);
  const clientDefaults = validateClientDefaults(config.clientDefaults);
  if (!testFixture && !needsSource && clientDefaults.gpgVerification === 'on') {
    if (!signed?.signature) throw Error('Verification-enabled static Git releases require a signed document and detached signature.');
    if (signed.metadata.listId !== clientDefaults.listId) throw Error('Client default list ID differs from the static signed document.');
    if (signedRelease?.fingerprint && clientDefaults.pinMode === 'primary' && clientDefaults.fingerprint !== signedRelease.fingerprint) throw Error('Client primary fingerprint differs from the configured signing certificate.');
  }
  let script = await readFile(join(directory,'conf-sshd.sh'),'utf8');
  for (const [name,value] of Object.entries({'BASE_URL':config.baseUrl,'DEFAULT_CRON':config.defaultCron})) {
    if (!script.includes(`@@${name}@@`)) throw Error(`Script is missing @@${name}@@.`);
    script = script.replaceAll(`@@${name}@@`,value);
  }
  for (const [name, value] of Object.entries({DEFAULT_GPG_VERIFY:clientDefaults.gpgVerification,DEFAULT_GPG_FINGERPRINT:clientDefaults.fingerprint,DEFAULT_GPG_PIN_MODE:clientDefaults.pinMode,DEFAULT_LIST_ID:clientDefaults.listId,DEFAULT_GPG_EMAIL:clientDefaults.email})) script = script.replaceAll(`@@${name}@@`, value);
  if (/@@[A-Z_]+@@/.test(script)) throw Error('Unresolved script template token.');
  if (!script.includes('# conf-sshd-script-v2')) throw Error('Missing script format marker.');
  execFileSync('sh',['-n'],{input:script,stdio:['pipe','pipe','pipe']});
  const release = {schema:1,revision,publishedAt,keyCount:keys.length,allowEmpty,sha256:bundle.sha256,keyRevision:signed?.metadata.documentSha256 ?? bundle.sha256,testFixture,baseUrl:config.baseUrl,repositoryUrl:config.repositoryUrl,fallbackSources,keySource,primaryFile,explicitEmpty,signedRelease,clientDefaults,publicCertificate,signedDocument:signed?.document ?? null,signature:signed?.signature ?? null,signatureAvailable:Boolean(signed?.signature),publicCertificateAvailable:Boolean(publicCertificate),signedBundle:signed?.bundle ?? null,signedMetadata:signed?.metadata ?? null,needsFallback,needsSource,keys,commands:commandsFor(config)};
  let html = await readFile(join(directory,'site/index.html'),'utf8');
  const publicDir = join(outDirectory,'public'), generatedDir = join(outDirectory,'generated');
  await rm(publicDir,{recursive:true,force:true});
  await mkdir(join(publicDir,'assets'),{recursive:true}); await mkdir(generatedDir,{recursive:true});
  // Git files are true Worker Static Assets as well as exact router response bytes (never Pages).
  if (!needsSource) await writeFile(join(publicDir,'ssh.keys'), signed?.document ?? bundle.text);
  if (signed?.signature) await writeFile(join(publicDir,'ssh.keys.sig'), signed.signature);
  if (publicCertificate) await writeFile(join(publicDir,'public-key.gpg'), publicCertificate);
  for (const [file,ext] of [['style','css'],['app','js']]) {
    const body = await readFile(join(directory,`site/assets/${file}.${ext}`));
    const name = `${file}.${digest(body).slice(0,12)}.${ext}`;
    await writeFile(join(publicDir,'assets',name),body);
    html = html.replaceAll(`/assets/${file}.${ext}`,`/assets/${name}`);
  }
  release.pageTemplate = html;
  await writeFile(join(publicDir,'index.html'),renderPage(html,{...release,source:{type:needsSource ? 'pending' : keys.length ? 'repository' : 'explicit-empty'}}));
  await writeFile(join(generatedDir,'release.js'),`// Generated release; do not edit.\nexport default ${JSON.stringify({...release,script,keysText:signed?.document ?? bundle.text})};\n`);
  await writeFile(join(generatedDir,'manifest.json'),JSON.stringify({...release,keys:undefined,commands:undefined,pageTemplate:undefined,publicCertificate:undefined,signedDocument:undefined,signature:undefined,signedBundle:undefined},null,2)+'\n');
  return release;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    if (args.some(arg=>arg !== '--test-fixture')) throw Error('Usage: node scripts/build.mjs [--test-fixture]');
    const release = await build({testFixture:args.includes('--test-fixture')});
    console.log(`Built ${release.testFixture ? 'TEST FIXTURE — NEVER DEPLOY' : 'production'} release ${release.revision}: ${release.keyCount} key(s).`);
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
