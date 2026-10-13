// Explicit external integration test. npm test imports this module but never
// invokes its network entry point. The public identity is a test-only fixture.
import {spawnSync} from 'node:child_process';
import {appendFileSync, chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const MAX_CERTIFICATE = 1024 * 1024;
const ATTEMPT_MS = 15_000;
// Deadline for starting/continuing network lookups. Each local verifier and
// private-agent cleanup also has its own timeout; CI supplies the hard job cap.
const NETWORK_BUDGET_MS = 120_000;
const MAX_ATTEMPTS = 2;
const fingerprint = value => typeof value === 'string' && /^[A-F0-9]{40}$/.test(value);

export function validateFixture(input) {
  if (!input || typeof input !== 'object' || !input.testOnlyNotice?.includes('integration-test identity only') ||
      typeof input.email !== 'string' || input.email.length > 254 || !/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$/.test(input.email) ||
      !fingerprint(input.primaryFingerprint) || !fingerprint(input.signingSubkeyFingerprint) ||
      input.primaryFingerprint === input.signingSubkeyFingerprint || !Array.isArray(input.keyservers) ||
      input.keyservers.length < 1 || input.keyservers.length > 4 ||
      input.keyservers.some(value => typeof value !== 'string' || !/^hkps:\/\/[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::[0-9]{1,5})?$/.test(value)) ||
      new Set(input.keyservers).size !== input.keyservers.length) throw Error('Invalid public integration-test fixture.');
  return input;
}

export function classifyFailure(result) {
  if (result.error?.code === 'ETIMEDOUT' || result.signal === 'SIGKILL') return 'timeout';
  if (result.error?.code === 'ENOENT') return 'missing-tool';
  if (result.error) return 'process-error';
  const diagnostic = String(result.stderr ?? '').toLowerCase();
  if (/no dirmngr|can.?t create socket|failed to start dirmngr|operation not permitted/.test(diagnostic)) return 'local-agent-unavailable';
  if (/timed? out|timeout/.test(diagnostic)) return 'timeout';
  if (/certificate.*(failed|invalid)|tls.*(failed|error)|not trusted/.test(diagnostic)) return 'transport-security-error';
  if (/network is unreachable|no route to host|could not resolve|name or service not known|network error|connection refused/.test(diagnostic)) return 'network-unavailable';
  if (/no data|not found|no public key/.test(diagnostic)) return 'key-not-found';
  return 'gpg-error';
}

export function execute(command, args, {home, timeout = ATTEMPT_MS} = {}) {
  return spawnSync(command, args, {
    encoding: 'utf8', timeout, killSignal: 'SIGKILL', maxBuffer: MAX_CERTIFICATE + 64 * 1024,
    env: {...process.env, LC_ALL: 'C', ...(home ? {HOME: home, GNUPGHOME: home} : {})},
  });
}

// Extract just the production verifier functions. Never source or run the
// installer, its argument parser, dependencies installer, or SSH configuration.
export function verifierHarness(clientSource) {
  const names = ['new_gpg_home', 'gpg_local', 'import_pinned_key'];
  const functions = names.map(name => {
    const matches = [...clientSource.matchAll(new RegExp(`^${name}\\(\\) \\{\\n[\\s\\S]*?^\\}\\n`, 'gm'))];
    if (matches.length !== 1) throw Error(`Cannot extract client verifier function: ${name}.`);
    return matches[0][0];
  }).join('\n');
  return `#!/bin/sh
set -eu
umask 077
LC_ALL=C
export LC_ALL
state=$1
certificate=$2
pinned_fingerprint=$3
pin_mode=$4
gpg_home=
temps=
fail() { printf 'client-certificate-rejected\\n' >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail; }
new_temp() { TEMP=$(mktemp "$1/verify.XXXXXX"); }
${functions}
import_pinned_key "$certificate"
printf '%s\\n' "$certificate_primary"
`;
}

export function validateCertificate(certificate, config, {
  clientSource = readFileSync(join(repositoryRoot, 'conf-sshd.sh'), 'utf8'), runner = execute,
} = {}) {
  if (typeof certificate !== 'string' || !certificate.length || Buffer.byteLength(certificate) > MAX_CERTIFICATE) return {ok: false, status: 'invalid-certificate-size'};
  const home = mkdtempSync(join(tmpdir(), 'conf-sshd-certificate-check-'));
  chmodSync(home, 0o700);
  try {
    const keyFile = join(home, 'public.asc'), harness = join(home, 'verify.sh');
    writeFileSync(keyFile, certificate, {mode: 0o600});
    writeFileSync(harness, verifierHarness(clientSource), {mode: 0o600});
    for (const mode of ['primary', 'subkey']) {
      // One clean home per pin mode, even though the function itself isolates its ring.
      const state = mkdtempSync(join(home, `${mode}-`));
      const pin = mode === 'primary' ? config.primaryFingerprint : config.signingSubkeyFingerprint;
      const result = runner('/bin/sh', [harness, state, keyFile, pin, mode], {home: state, timeout: ATTEMPT_MS});
      if (result.status !== 0 || result.error || result.stdout?.trim() !== config.primaryFingerprint) {
        return {ok: false, status: result.error ? classifyFailure(result) : 'certificate-pin-or-capability-rejected', mode};
      }
    }
    return {ok: true, status: 'validated-primary-and-subkey'};
  } finally {
    // The extracted verifier uses --no-autostart and a public-only keyring.
    rmSync(home, {recursive: true, force: true});
  }
}

export function discoveryProbes(config) {
  return [
    {source: 'wkd', queryMode: 'email', args: ['--auto-key-locate', 'clear,wkd', '--locate-external-keys', '--', config.email]},
    ...config.keyservers.map(server => ({
      source: server, queryMode: 'primary',
      args: ['--auto-key-locate', 'clear', '--keyserver', server, '--recv-keys', config.primaryFingerprint],
    })),
  ];
}

export function runDiscovery(config, {runner = execute, validator = validateCertificate, now = Date.now} = {}) {
  validateFixture(config);
  const start = now(), deadline = start + NETWORK_BUDGET_MS, results = [];
  for (const probe of discoveryProbes(config)) {
    let status = 'budget-exhausted', attempts = 0;
    for (; attempts < MAX_ATTEMPTS;) {
      const remaining = deadline - now();
      if (remaining <= 0) { status = 'budget-exhausted'; break; }
      attempts++;
      const home = mkdtempSync(join(tmpdir(), 'conf-sshd-live-discovery-'));
      chmodSync(home, 0o700);
      try {
        const base = ['--batch', '--no-options', '--homedir', home, '--no-tty', '--no-auto-key-retrieve'];
        const fetched = runner('gpg', [...base, '--status-fd', '1', ...probe.args], {home, timeout: Math.min(ATTEMPT_MS, remaining)});
        if (fetched.status !== 0 || fetched.error) {
          status = classifyFailure(fetched);
        } else {
          const exportRemaining = deadline - now();
          if (exportRemaining <= 0) { status = 'budget-exhausted'; break; }
          const exported = runner('gpg', [...base, '--no-autostart', '--auto-key-locate', 'clear', '--armor', '--export'], {home, timeout: Math.min(ATTEMPT_MS, exportRemaining)});
          if (exported.status !== 0 || exported.error) status = `export-${classifyFailure(exported)}`;
          else {
            const validation = validator(exported.stdout, config);
            status = validation.ok ? 'passed' : validation.status;
            // A fetched but invalid certificate is a security failure, not a reason
            // to hide the result by retrying until the server returns another key.
            break;
          }
        }
      } finally {
        // Only services associated with this newly created private home are stopped.
        runner('gpgconf', ['--homedir', home, '--kill', 'all'], {home, timeout: 5000});
        rmSync(home, {recursive: true, force: true});
      }
      if (!['timeout', 'network-unavailable', 'key-not-found', 'gpg-error'].includes(status)) break;
    }
    results.push({source: probe.source, queryMode: probe.queryMode, status, attempts,
      primaryFingerprint: config.primaryFingerprint, signingSubkeyFingerprint: config.signingSubkeyFingerprint});
  }
  return {schema: 'conf-sshd-live-discovery-v1', status: results.every(result => result.status === 'passed') ? 'passed' : 'failed', results};
}

export function summaryMarkdown(report) {
  return ['## Public GPG discovery integration test', '',
    `Overall: ${report.status}. Every source must pass; infrastructure failures are not skips.`, '',
    ...report.results.map(result => `- ${result.source} (${result.queryMode}): ${result.status}; attempts ${result.attempts}; primary ${result.primaryFingerprint ?? 'unavailable'}; signing subkey ${result.signingSubkeyFingerprint ?? 'unavailable'}`), '',
    'This tests public certificate discovery and the client pin/capability checks. No user-signed key-list payload is tested, and no SSH or persistent user trust settings are changed.', ''].join('\n');
}

export function main() {
  let report;
  try {
    const config = validateFixture(JSON.parse(readFileSync(join(repositoryRoot, 'tests/fixtures/live-discovery.json'), 'utf8')));
    const missing = ['gpg', 'dirmngr', 'gpgconf'].find(command => execute(command, ['--version'], {timeout: 5000}).status !== 0);
    report = missing ? {schema: 'conf-sshd-live-discovery-v1', status: 'failed', results: [{source: 'local-tools', queryMode: 'none', status: 'missing-tool', attempts: 0,
      primaryFingerprint: config.primaryFingerprint, signingSubkeyFingerprint: config.signingSubkeyFingerprint}]} : runDiscovery(config);
  } catch {
    report = {schema: 'conf-sshd-live-discovery-v1', status: 'failed', results: [{source: 'local-harness', queryMode: 'none', status: 'fixture-or-harness-error', attempts: 0}]};
  }
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, summaryMarkdown(report));
  return report.status === 'passed' ? 0 : 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = main();
