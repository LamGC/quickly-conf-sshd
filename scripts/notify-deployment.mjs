// Optional JSON webhook for a separately configured email delivery service.
// This sends deployment configuration, not observed server/fleet state.
import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

export function notificationEnabled(value) {
  if (value === undefined || value === '' || value === 'false') return false;
  if (value === 'true') return true;
  throw Error('ENABLE_MAIL_NOTIFICATION must be unset, false, or exactly true.');
}

function httpsUrl(value, name) {
  let url;
  try { url = new URL(value); } catch { throw Error(`${name} must be an HTTPS URL.`); }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) throw Error(`${name} must be HTTPS without URL credentials or fragments.`);
  return url.href;
}

export function deploymentPayload(config, env) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) throw Error('Deployment configuration must be an object.');
  const status = env.DEPLOYMENT_STATUS;
  if (!['success','failure','cancelled'].includes(status)) throw Error('DEPLOYMENT_STATUS must be success, failure, or cancelled.');
  const phase = env.DEPLOYMENT_PHASE;
  if (!['deployment','remote-verification','complete'].includes(phase)) throw Error('DEPLOYMENT_PHASE must identify the attempted deployment phase.');
  if (!/^[0-9a-f]{40}$/.test(env.GITHUB_SHA || '')) throw Error('GITHUB_SHA must be an exact 40-hex commit SHA.');
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(env.GITHUB_REPOSITORY || '') || !/^\d+$/.test(env.GITHUB_RUN_ID || '')) throw Error('A valid GitHub repository and run ID are required.');
  const mode = config.keySource?.type ?? 'git';
  if (!['git','gist'].includes(mode)) throw Error('Unsupported deployment key source mode.');
  const listId = config.signedRelease?.listId ?? null;
  if (listId !== null && (typeof listId !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/.test(listId))) throw Error('Invalid deployment list identity.');
  const fallbackSources = config.fallbackSources ?? [];
  if (!Array.isArray(fallbackSources) || fallbackSources.length > 5) throw Error('Invalid deployment fallback sources.');
  const to = env.MAIL_NOTIFICATION_TO || null;
  if (to !== null && (to.length > 254 || !/^[^\s@,<>]+@[^\s@,<>]+\.[^\s@,<>]+$/.test(to))) throw Error('MAIL_NOTIFICATION_TO must be one email address.');
  return {
    schema:1,
    event:'worker-deployment',
    status,
    phase,
    repository:env.GITHUB_REPOSITORY,
    revision:env.GITHUB_SHA,
    workflowRunUrl:`https://github.com/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}`,
    to,
    configuration:{
      baseUrl:httpsUrl(config.baseUrl, 'Deployment baseUrl'),
      mode,
      listId,
      signedRelease:Boolean(config.signedRelease),
      fallbackSources:fallbackSources.map(value => httpsUrl(value,'Deployment fallback source')),
    },
    configurationScope:'deployment configuration only; not measured server state',
  };
}

export async function notifyDeployment({env = process.env, config, fetchImpl = globalThis.fetch} = {}) {
  if (!notificationEnabled(env.ENABLE_MAIL_NOTIFICATION)) return {sent:false,reason:'disabled'};
  if (env.GITHUB_ACTIONS !== 'true' || env.CI !== 'true') throw Error('Deployment notification sending is allowed only in GitHub Actions CI.');
  if (!env.MAIL_NOTIFICATION_WEBHOOK) throw Error('MAIL_NOTIFICATION_WEBHOOK is required when notifications are enabled.');
  const endpoint = httpsUrl(env.MAIL_NOTIFICATION_WEBHOOK,'Notification webhook');
  const payload = deploymentPayload(config,env);
  let response;
  try {
    response = await fetchImpl(endpoint, {
      method:'POST',
      headers:{'content-type':'application/json'},
      body:JSON.stringify(payload),
      redirect:'error',
      signal:AbortSignal.timeout(10_000),
    });
  } catch {
    // Provider errors may contain secret URL tokens. Do not print them or retry
    // automatically: a timed-out request may already have sent the email.
    throw Error('Deployment notification request failed; check the webhook service.');
  }
  if (!response.ok) throw Error(`Deployment notification was rejected (HTTP ${response.status}).`);
  // Do not log response bodies, the recipient, or the secret webhook URL.
  return {sent:true};
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 2) throw Error('Usage: node scripts/notify-deployment.mjs');
    let config;
    if (notificationEnabled(process.env.ENABLE_MAIL_NOTIFICATION)) {
      try { config = JSON.parse(await readFile(new URL('../deployment.json',import.meta.url),'utf8')); }
      catch { throw Error('Cannot read deployment notification configuration.'); }
    }
    const result = await notifyDeployment({config});
    console.log(result.sent ? 'Deployment notification webhook accepted the request.' : 'Deployment notification disabled.');
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
