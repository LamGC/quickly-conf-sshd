import { readFile, writeFile, mkdir, rm, mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';

export const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const digest = data => createHash('sha256').update(data).digest('hex');
import { escapeHTML, commandsFor, renderKeys, renderCommands, renderPage } from '../cf-worker/src/view.js';
export { escapeHTML, commandsFor, renderKeys, renderCommands };
import { validateFallbackSources, parsePublicKeys } from '../cf-worker/src/key-source.js';


export function validateConfig(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) throw Error('Deployment configuration must be an object.');
  for (const key of Object.keys(config)) if (!['baseUrl','repositoryUrl','defaultCron','allowEmpty','fallbackSources'].includes(key)) throw Error(`Unknown configuration: ${key}`);
  if (typeof config.baseUrl !== 'string' || !/^https:\/\/[a-zA-Z0-9.-]+(?::[0-9]+)?$/.test(config.baseUrl)) throw Error('baseUrl must be an HTTPS origin without paths, credentials, or shell metacharacters.');
  const url = new URL(config.baseUrl);
  if (url.origin !== config.baseUrl || !url.hostname.includes('.') || url.hostname.includes('..')) throw Error('baseUrl must be a canonical HTTPS origin.');
  if (typeof config.repositoryUrl !== 'string' || !/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(config.repositoryUrl)) throw Error('repositoryUrl must identify a GitHub repository.');
  if (typeof config.allowEmpty !== 'boolean') throw Error('allowEmpty must be an explicit boolean.');
  validateFallbackSources(Object.hasOwn(config, 'fallbackSources') ? config.fallbackSources : []);
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
  if (!keys.length && !allowEmpty) throw Error('No server public keys configured. Add keys/authorized_keys, or explicitly allow an empty revocation release.');
  const payload = keys.map(key => key.text + '\n').join('');
  const sha256 = digest(payload);
  const text = `# conf-sshd-v1\n# revision ${revision}\n# key-count ${keys.length}\n# allow-empty ${allowEmpty ? 'yes' : 'no'}\n# sha256 ${sha256}\n# end-metadata\n${payload}`;
  if (Buffer.byteLength(text) > 1024 * 1024) throw Error('Serialized key release exceeds client response limit.');
  return {sha256,text};
}


export async function build({directory = root, outDirectory = join(directory,'cf-worker'), testFixture = false, revision, publishedAt} = {}) {
  const config = validateConfig(JSON.parse(await readFile(join(directory,'deployment.json'),'utf8')));
  const input = await readFile(join(directory,testFixture ? 'tests/fixtures/keys.pub' : 'keys/authorized_keys'),'utf8');
  const keys = await parseKeys(input);
  revision ||= process.env.GITHUB_SHA || execFileSync('git',['rev-parse','HEAD'],{cwd:directory,encoding:'utf8'}).trim();
  publishedAt ||= new Date().toISOString();
  const fallbackSources = validateFallbackSources(config.fallbackSources ?? []);
  const needsFallback = keys.length === 0 && !config.allowEmpty && fallbackSources.length > 0;
  const bundle = needsFallback ? {sha256:null,text:null} : makeKeysText(keys,revision,config.allowEmpty);
  let script = await readFile(join(directory,'conf-sshd.sh'),'utf8');
  for (const [name,value] of Object.entries({'BASE_URL':config.baseUrl,'DEFAULT_CRON':config.defaultCron})) {
    if (!script.includes(`@@${name}@@`)) throw Error(`Script is missing @@${name}@@.`);
    script = script.replaceAll(`@@${name}@@`,value);
  }
  if (/@@[A-Z_]+@@/.test(script)) throw Error('Unresolved script template token.');
  if (!script.includes('# conf-sshd-script-v2')) throw Error('Missing script format marker.');
  execFileSync('sh',['-n'],{input:script,stdio:['pipe','pipe','pipe']});
  const release = {schema:1,revision,publishedAt,keyCount:keys.length,allowEmpty:config.allowEmpty,sha256:bundle.sha256,testFixture,baseUrl:config.baseUrl,repositoryUrl:config.repositoryUrl,fallbackSources,needsFallback,keys,commands:commandsFor(config)};
  let html = await readFile(join(directory,'site/index.html'),'utf8');
  const publicDir = join(outDirectory,'public'), generatedDir = join(outDirectory,'generated');
  await rm(publicDir,{recursive:true,force:true});
  await mkdir(join(publicDir,'assets'),{recursive:true}); await mkdir(generatedDir,{recursive:true});
  for (const [file,ext] of [['style','css'],['app','js']]) {
    const body = await readFile(join(directory,`site/assets/${file}.${ext}`));
    const name = `${file}.${digest(body).slice(0,12)}.${ext}`;
    await writeFile(join(publicDir,'assets',name),body);
    html = html.replaceAll(`/assets/${file}.${ext}`,`/assets/${name}`);
  }
  release.pageTemplate = html;
  await writeFile(join(publicDir,'index.html'),renderPage(html,{...release,source:{type:needsFallback ? 'pending' : keys.length ? 'repository' : 'explicit-empty'}}));
  await writeFile(join(generatedDir,'release.js'),`// Generated release; do not edit.\nexport default ${JSON.stringify({...release,script,keysText:bundle.text})};\n`);
  await writeFile(join(generatedDir,'manifest.json'),JSON.stringify({...release,keys:undefined,commands:undefined,pageTemplate:undefined},null,2)+'\n');
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
