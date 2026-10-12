import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {parsePublicKeys} from '../cf-worker/src/key-source.js';
const manifest=JSON.parse(await readFile(new URL('../cf-worker/generated/manifest.json',import.meta.url),'utf8'));
if (manifest.testFixture) throw Error('Refusing to deploy a test-fixture build. Run the production build with real server public keys.');
if (!process.argv.includes('--remote')) { console.log(`Production release verified: ${manifest.revision}`); }
else {
  const timeout=()=>AbortSignal.timeout(20000);
  const metadataResponse=await fetch(manifest.baseUrl+'/release.json',{cache:'no-store',signal:timeout()});
  if(!metadataResponse.ok) throw Error(`Metadata endpoint returned ${metadataResponse.status}`);
  const metadata=await metadataResponse.json();
  if(metadata.revision!==manifest.revision||metadata.testFixture) throw Error('Remote release does not match this build.');
  if(!/^[0-9a-f]{64}$/.test(metadata.sha256)) throw Error('Remote key digest is invalid.');
  if(manifest.needsFallback) {
    if(metadata.source?.type!=='fallback'||!manifest.fallbackSources.includes(metadata.source.url)||metadata.keyCount<1)throw Error('Unexpected effective fallback source.');
  } else if(metadata.sha256!==manifest.sha256) throw Error('Remote repository keys differ from this build.');
  const keysResponse=await fetch(manifest.baseUrl+'/ssh.keys',{cache:'no-store',signal:timeout()});
  if(!keysResponse.ok) throw Error(`Keys endpoint returned ${keysResponse.status}`);
  const keysText=await keysResponse.text();
  const match=/^# conf-sshd-v1\n# revision ([0-9a-f]{40})\n# key-count (0|[1-9][0-9]*)\n# allow-empty (yes|no)\n# sha256 ([0-9a-f]{64})\n# end-metadata\n([\s\S]*)$/.exec(keysText);
  if(!match||match[1]!==manifest.revision)throw Error('Remote key manifest invalid.');
  const [, , count, empty, hash, payload]=match;
  if(createHash('sha256').update(payload).digest('hex')!==hash) throw Error('Remote key body does not match its response digest.');
  const keys=await parsePublicKeys(payload);
  if(keys.length!==Number(count)||(!keys.length&&(!manifest.allowEmpty||empty!=='yes')))throw Error('Remote key count/empty policy invalid.');
  if(!manifest.needsFallback&&hash!==manifest.sha256)throw Error('Remote repository key payload differs from this build.');
  // Dynamic fallback may legitimately change between the two requests; each response is checked independently.
  console.log(`Remote code release verified: ${metadata.revision}; key payload ${hash} (${count} keys).`);
}
