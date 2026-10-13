import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,mkdtemp,cp,writeFile,rm,mkdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {renderPage} from '../cf-worker/src/view.js';
import {validateConfig,parseKeys,makeKeysText,commandsFor,build,root,digest} from '../scripts/build.mjs';
const config = {baseUrl:'https://ssh.example.com',repositoryUrl:'https://github.com/example/keys',defaultCron:'*/15 * * * *',allowEmpty:false};
const fixture = await readFile(new URL('./fixtures/keys.pub',import.meta.url),'utf8');
const canonicalFixture=fixture.trim().split(/ +/).slice(0,2).join(' ')+'\n';

test('deployment configuration rejects shell injection and ambiguous origins',()=>{
  assert.deepEqual(validateConfig(config),config);
  for(const baseUrl of ['http://x.example','https://user@x.example','https://x.example/','https://x.example/a','https://x.example;touch /tmp/x','https://x.example\n','https://x.example$(id)','https://x.example:443']) assert.throws(()=>validateConfig({...config,baseUrl}));
  for(const defaultCron of ['* * * * *\nevil','61 * * * *','*/0 * * * *','*/99 * * * *','* * * 13 *','* * * * * echo x']) assert.throws(()=>validateConfig({...config,defaultCron}));
  assert.throws(()=>validateConfig({...config,allowEmpty:'false'}));
  assert.throws(()=>validateConfig({...config,sshKeyUrl:'https://github.com/user.keys'}));
});
test('keys are structurally validated, canonicalized and fingerprinted',async()=>{
  const keys = await parseKeys('# a comment\r\n'+fixture.replace(/\n/g,'\r\n'));
  assert.equal(keys.length,1);assert.match(keys[0].fingerprint,/^SHA256:/);
  assert.equal(keys[0].text+'\n',fixture);
  assert.equal((await parseKeys(fixture.trimEnd())).length,1);
});
test('rejects malformed keys, options, duplicate identities, private material and NUL',async()=>{
  const key = fixture.trim();const [type,blob] = key.split(' ');
  for(const input of ['ssh-ed25519 not-a-key','ssh-rsa '+blob,`command="evil" ${key}`,`${key}\n${type} ${blob} different-comment`,'-----BEGIN OPENSSH PRIVATE KEY-----',key+'\0',`ssh-dss ${blob}`]) await assert.rejects(parseKeys(input));
});
test('empty revocation must be explicit; protocol is deterministic',async()=>{
  assert.throws(()=>makeKeysText([], 'a'.repeat(40),false),/No server public keys/);
  const empty = makeKeysText([], 'a'.repeat(40),true);
  assert.match(empty.text,/# key-count 0\n# allow-empty yes\n/);assert.equal(empty.sha256,digest(''));
  const keys=await parseKeys(fixture);const bundle=makeKeysText(keys,'b'.repeat(40),false);
  assert.ok(bundle.text.endsWith(canonicalFixture));assert.equal(bundle.sha256,digest(canonicalFixture));
  assert.throws(()=>makeKeysText(keys,'main',false),/commit SHA/);
});
test('homepage excludes keys and commands use explicit install and fixed local sync',async()=>{
  const commands=commandsFor(config);
  assert.ok(commands.find(x=>x.id==='install').command.includes('--install'));
  assert.equal(Boolean(commands.find(x=>x.id==='root-on').advanced), false);
  assert.ok(commands.find(x=>x.id==='root-off').advanced);
  assert.ok(commandsFor({...config,defaultCron:'0 */6 * * *'})[0].description.includes('0 */6 * * *'));
  assert.ok(commands.find(x=>x.id==='uninstall').advanced);
  assert.ok(commands.every(x=>!x.command.includes('github.io')));
  assert.ok(!commands.some(x=>/ -u$/.test(x.command)));
  assert.ok(commands.find(x=>x.id==='once').command.includes('$HOME/.conf-sshd/conf-sshd.sh'));
});
test('build creates consistent assets/release; production empty is blocked',async()=>{
  const directory=await mkdtemp(join(tmpdir(),'conf-sshd-build-'));
  try {
    for(const path of ['site','tests/fixtures','keys']) {await mkdir(join(directory,path),{recursive:true});await cp(join(root,path),join(directory,path),{recursive:true});}
    await cp(join(root,'conf-sshd.sh'),join(directory,'conf-sshd.sh'));
    await writeFile(join(directory,'deployment.json'),JSON.stringify(config));
    const options={directory,revision:'c'.repeat(40),publishedAt:'2026-10-12T00:00:00.000Z'};
    await assert.rejects(build(options),/No server public keys/);
    const release=await build({...options,testFixture:true});assert.equal(release.testFixture,true);
    const html=await readFile(join(directory,'cf-worker/public/index.html'),'utf8');
    assert.ok(!html.includes('@@'));assert.ok(html.includes('cccccccccccc'));assert.match(html,/\/assets\/app\.[a-f0-9]{12}\.js/);
    const generated=await readFile(join(directory,'cf-worker/generated/release.js'),'utf8');
    assert.ok(generated.includes('# conf-sshd-v1'));assert.ok(generated.includes('https://ssh.example.com'));assert.ok(!generated.includes('@@BASE_URL@@'));
    await writeFile(join(directory,'keys/authorized_keys'),fixture);
    assert.equal((await build(options)).testFixture,false);
  } finally {await rm(directory,{recursive:true,force:true});}
});

test('fallback configuration allows an empty primary only with explicit bounded HTTPS sources',async()=>{
  assert.throws(()=>validateConfig({...config,fallbackSources:['http://keys.example.com']}));
  assert.throws(()=>validateConfig({...config,fallbackSources:['https://user:secret@keys.example.com']}));
  assert.throws(()=>validateConfig({...config,fallbackSources:Array(6).fill('https://keys.example.com')}));
  const directory=await mkdtemp(join(tmpdir(),'conf-sshd-fallback-build-'));
  try {
    for(const path of ['site','tests/fixtures','keys']) {await mkdir(join(directory,path),{recursive:true});await cp(join(root,path),join(directory,path),{recursive:true});}
    await cp(join(root,'conf-sshd.sh'),join(directory,'conf-sshd.sh'));
    await writeFile(join(directory,'deployment.json'),JSON.stringify({...config,fallbackSources:['https://keys.example.com/server.keys']}));
    const release=await build({directory,revision:'d'.repeat(40)});
    assert.equal(release.needsFallback,true);assert.equal(release.sha256,null);assert.equal(release.keyCount,0);
    assert.ok((await readFile(join(directory,'cf-worker/public/index.html'),'utf8')).includes('未发布撤销指令'));
  } finally {await rm(directory,{recursive:true,force:true});}
});

test('template rendering excludes even adversarial key comments from HTML and JSON',async()=>{
  const tricky=fixture.trim()+" $& $` $' $$ @@REVISION@@ @@KEYS_HTML@@";
  const keys=await parseKeys(tricky);
  const template='<div>@@SOURCE_LABEL@@</div><script type="application/json">@@RELEASE_JSON@@</script>';
  const html=renderPage(template,{revision:'e'.repeat(40),publishedAt:'2026-10-12',keys,commands:[],repositoryUrl:config.repositoryUrl,sha256:'f'.repeat(64)});
  const json=JSON.parse(html.match(/<script type="application\/json">([\s\S]*?)<\/script>/)[1]);
  assert.equal(json.keys,undefined);assert.ok(!html.includes(keys[0].text));assert.ok(!html.includes(keys[0].fingerprint));
  assert.throws(()=>renderPage('@@UNKNOWN@@',{revision:'e'.repeat(40),keys:[]}),/Unresolved/);
});
