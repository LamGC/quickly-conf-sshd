import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,mkdtemp,cp,writeFile,rm,mkdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {renderPage} from '../cf-worker/src/view.js';
import {validateConfig,parseKeys,makeKeysText,commandsFor,build,root,digest} from '../scripts/build.mjs';
import {verifyProduction} from '../scripts/verify-release.mjs';
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

test('fallback URLs cannot bypass the unconfigured-primary deployment gate',async()=>{
  assert.throws(()=>validateConfig({...config,fallbackSources:['http://keys.example.com']}));
  assert.throws(()=>validateConfig({...config,fallbackSources:['https://user:secret@keys.example.com']}));
  assert.throws(()=>validateConfig({...config,fallbackSources:Array(6).fill('https://keys.example.com')}));
  const directory=await mkdtemp(join(tmpdir(),'conf-sshd-fallback-build-'));
  try {
    for(const path of ['site','tests/fixtures','keys']) {await mkdir(join(directory,path),{recursive:true});await cp(join(root,path),join(directory,path),{recursive:true});}
    await cp(join(root,'conf-sshd.sh'),join(directory,'conf-sshd.sh'));
    await writeFile(join(directory,'deployment.json'),JSON.stringify({...config,fallbackSources:['https://keys.example.com/server.keys']}));
    await assert.rejects(build({directory,revision:'d'.repeat(40)}),/No server public keys configured/);
  } finally {await rm(directory,{recursive:true,force:true});}
});

test('production distinguishes missing/comment-only files from deliberate blank revocations',async()=>{
  const directory=await mkdtemp(join(tmpdir(),'conf-sshd-primary-build-'));
  try {
    for(const path of ['site','tests/fixtures','keys']) await cp(join(root,path),join(directory,path),{recursive:true});
    await cp(join(root,'conf-sshd.sh'),join(directory,'conf-sshd.sh'));
    const keyPath=join(directory,'keys/authorized_keys'), options={directory,revision:'e'.repeat(40)};
    for(const allowEmpty of [false,true]) for(const fallbackSources of [[],['https://keys.example.com/server.keys']]) {
      await writeFile(join(directory,'deployment.json'),JSON.stringify({...config,allowEmpty,fallbackSources}));
      for(const content of [null,'# Add server keys here.\n','# placeholder\n \t\n']) {
        if(content===null) await rm(keyPath,{force:true}); else await writeFile(keyPath,content);
        await assert.rejects(build(options),/No server public keys configured/);
      }
      for(const content of ['',' ','\n','\r',' \t\r\n\t ']) {
        await writeFile(keyPath,content);
        const release=await build(options);
        assert.equal(release.primaryFile,'keys/authorized_keys');assert.equal(release.allowEmpty,true);assert.equal(release.explicitEmpty,true);
        assert.equal(release.needsFallback,false);assert.equal(release.needsSource,false);assert.equal(release.keyCount,0);
        assert.equal(release.sha256,digest(''));assert.equal(release.signatureAvailable,false);
        assert.match(await readFile(join(directory,'cf-worker/public/ssh.keys'),'utf8'),/# key-count 0\n# allow-empty yes\n/);
        assert.match(await verifyProduction(release,()=>assert.fail('Git revocation must not fetch fallback')),/0 key\(s\) from explicit-empty/);
      }
      await writeFile(keyPath,fixture);
      const release=await build(options);assert.equal(release.keyCount,1);
      assert.match(await verifyProduction(release,()=>assert.fail('Git primary must not fetch fallback')),/1 key\(s\) from repository/);
    }
    for(const content of ['\u00a0','\v','\0','\r'.repeat(1024*1024+1)]) {
      await writeFile(keyPath,content);
      await assert.rejects(build(options));
    }
    await rm(keyPath);
    const fixtureRelease=await build({...options,testFixture:true});
    assert.equal(fixtureRelease.testFixture,true);assert.equal(fixtureRelease.keyCount,1);
    await assert.rejects(verifyProduction(fixtureRelease),/test-fixture/);
  } finally {await rm(directory,{recursive:true,force:true});}
});

test('ON builds never turn a blank unsigned Git file into a signed revoke',async()=>{
  const directory=await mkdtemp(join(tmpdir(),'conf-sshd-on-empty-'));
  try {
    await cp(join(root,'site'),join(directory,'site'),{recursive:true});await mkdir(join(directory,'keys'));
    await cp(join(root,'conf-sshd.sh'),join(directory,'conf-sshd.sh'));
    await writeFile(join(directory,'deployment.json'),JSON.stringify({...config,allowEmpty:true,fallbackSources:['https://keys.example.com/server.keys'],clientDefaults:{gpgVerification:'on',fingerprint:'A'.repeat(40),listId:'production'}}));
    await writeFile(join(directory,'keys/authorized_keys'),'\n');
    await assert.rejects(build({directory,revision:'f'.repeat(40)}),/require a signed document/);
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
