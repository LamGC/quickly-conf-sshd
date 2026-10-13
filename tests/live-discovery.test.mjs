// Hermetic tests only. The network CLI is deliberately not invoked here.
import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync, readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {openPgpFixture} from './helpers/openpgp-fixture.mjs';
import {classifyFailure, discoveryProbes, runDiscovery, summaryMarkdown, validateCertificate, validateFixture, verifierHarness} from '../scripts/test-live-discovery.mjs';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/live-discovery.json', import.meta.url), 'utf8'));
const clientSource = readFileSync(new URL('../conf-sshd.sh', import.meta.url), 'utf8');
const gpgAvailable = spawnSync('gpg', ['--version']).status === 0;

test('fixed public discovery identity is explicitly test-only and full-pinned', () => {
  assert.equal(validateFixture(fixture), fixture);
  assert.equal(fixture.email, 'lam827@lamgc.net');
  assert.equal(fixture.primaryFingerprint, '7EF5FB1E65C1A6C6D02DFCDFCE57746D7E5EE6EF');
  assert.equal(fixture.signingSubkeyFingerprint, 'B1B89449E5877614EA672F5F6C5AE2A913941E1D');
  for (const change of [{primaryFingerprint: 'CE57746D7E5EE6EF'}, {testOnlyNotice: ''}, {email: 'bad\naddress'}, {keyservers: ['http://bad.example']}, {signingSubkeyFingerprint: fixture.primaryFingerprint}]) {
    assert.throws(() => validateFixture({...fixture, ...change}), /Invalid/);
  }
});

test('discovery probes cover WKD and each HKPS independently using the full primary pin', () => {
  const probes = discoveryProbes(fixture);
  assert.equal(probes.length, 3);
  assert.deepEqual(probes[0].args.slice(-3), ['--locate-external-keys', '--', fixture.email]);
  for (const probe of probes.slice(1)) {
    assert.deepEqual(probe.args.slice(-2), ['--recv-keys', fixture.primaryFingerprint]);
    assert.equal(probe.queryMode, 'primary');
  }
});

test('network and local failures are classified without exposing diagnostic text', () => {
  for (const [result, expected] of [
    [{error: {code: 'ETIMEDOUT'}}, 'timeout'], [{signal: 'SIGKILL'}, 'timeout'],
    [{error: {code: 'ENOENT'}}, 'missing-tool'], [{error: {code: 'EACCES'}}, 'process-error'],
    [{stderr: 'gpg: Connection timed out'}, 'timeout'], [{stderr: 'Network is unreachable'}, 'network-unavailable'],
    [{stderr: 'gpg: error: No data'}, 'key-not-found'], [{stderr: 'TLS certificate verification failed'}, 'transport-security-error'],
    [{stderr: 'No dirmngr'}, 'local-agent-unavailable'], [{stderr: "can't create socket"}, 'local-agent-unavailable'],
    [{stderr: 'failed to start dirmngr'}, 'local-agent-unavailable'], [{stderr: 'Operation not permitted'}, 'local-agent-unavailable'],
    [{stderr: 'Private unrelated UID value'}, 'gpg-error'],
  ]) assert.equal(classifyFailure(result), expected);
});

test('unavailable network is a failing report, retries are bounded, and every attempt uses a fresh home', () => {
  const homes = [], calls = [];
  const report = runDiscovery(fixture, {
    runner(command, args, options) {
      calls.push({command, args, options});
      if (command === 'gpgconf') return {status: 0};
      homes.push(options.home);
      assert.ok(options.timeout <= 15_000);
      assert.ok(args.includes('--no-options'));
      assert.ok(args.includes('--no-auto-key-retrieve'));
      return {status: 2, stderr: 'Network is unreachable. Unrelated UID must never appear.'};
    },
    validator() { assert.fail('No certificate should be validated after a failed lookup.'); },
  });
  assert.equal(report.status, 'failed');
  assert.equal(report.results.length, 3);
  assert.ok(report.results.every(result => result.status === 'network-unavailable' && result.attempts === 2));
  assert.equal(new Set(homes).size, 6);
  assert.ok(homes.every(home => !existsSync(home)));
  assert.equal(calls.filter(call => call.command === 'gpgconf').length, 6);
  assert.doesNotMatch(JSON.stringify(report) + summaryMarkdown(report), /Unrelated UID/);
});

test('a missing tool and exhausted budget fail rather than becoming skipped passes', () => {
  const missing = runDiscovery(fixture, {runner: () => ({status: null, error: {code: 'ENOENT'}})});
  assert.equal(missing.status, 'failed');
  assert.ok(missing.results.every(result => result.status === 'missing-tool' && result.attempts === 1));
  const localAgent = runDiscovery(fixture, {runner: () => ({status: 2, stderr: 'gpg: failed to start dirmngr'})});
  assert.equal(localAgent.status, 'failed');
  assert.ok(localAgent.results.every(result => result.status === 'local-agent-unavailable' && result.attempts === 1));
  let ticks = 0;
  const budget = runDiscovery(fixture, {now: () => ticks++ * 120_001, runner: () => assert.fail('Budget-exhausted test must not invoke tools.')});
  assert.equal(budget.status, 'failed');
  assert.ok(budget.results.every(result => result.status === 'budget-exhausted' && result.attempts === 0));
});

test('fetched invalid certificates cannot be retried into apparent success', () => {
  let validations = 0;
  const report = runDiscovery(fixture, {
    runner(command, args) {return {status: 0, stdout: args.includes('--export') ? 'untrusted certificate bytes' : ''};},
    validator() { validations++; return {ok: false, status: 'certificate-pin-or-capability-rejected'}; },
  });
  assert.equal(report.status, 'failed');
  assert.equal(validations, 3);
  assert.ok(report.results.every(result => result.attempts === 1 && result.status === 'certificate-pin-or-capability-rejected'));
});

test('successful discovery validates each exported certificate and reports no raw bytes', () => {
  const certificates = [];
  const report = runDiscovery(fixture, {
    runner(command, args) {return {status: 0, stdout: args.includes('--export') ? 'public certificate fixture bytes' : ''};},
    validator(certificate, config) {certificates.push(certificate);assert.equal(config, fixture);return {ok: true};},
  });
  assert.equal(report.status, 'passed');
  assert.equal(certificates.length, 3);
  assert.ok(report.results.every(result => result.status === 'passed'));
  assert.doesNotMatch(JSON.stringify(report), /public certificate fixture bytes/);
  assert.match(summaryMarkdown(report), /No user-signed key-list payload is tested/);
});

test('verifier harness extracts production certificate functions but never executes installer dispatch', () => {
  const harness = verifierHarness(clientSource);
  for (const name of ['new_gpg_home', 'gpg_local', 'import_pinned_key']) assert.ok(harness.includes(`${name}() {`));
  for (const forbidden of ['install_dependency()', 'prepare_sshd_config()', 'case $mode in', 'load_local_config()']) assert.ok(!harness.includes(forbidden));
  assert.throws(() => verifierHarness('not an installer'), /Cannot extract/);
});

test('actual client verifier accepts real local primary and signing-subkey pins and rejects unsafe certificates', {skip: !gpgAvailable}, () => {
  const key = openPgpFixture({subkeys: 2});
  const config = {...fixture, primaryFingerprint: key.primaryFingerprint, signingSubkeyFingerprint: key.signerFingerprint};
  assert.equal(validateCertificate(key.publicKey, config).ok, true);
  assert.equal(validateCertificate(key.publicKey, {...config, signingSubkeyFingerprint: key.signerFingerprints[1]}).ok, true);
  assert.equal(validateCertificate(key.publicKey, {...config, primaryFingerprint: 'A'.repeat(40)}).ok, false);
  assert.equal(validateCertificate(key.publicKey, {...config, signingSubkeyFingerprint: 'B'.repeat(40)}).ok, false);
  for (const options of [{expired: true}, {revoked: true}]) {
    const invalid = openPgpFixture({subkeys: 1, ...options});
    assert.equal(validateCertificate(invalid.publicKey, {...fixture, primaryFingerprint: invalid.primaryFingerprint, signingSubkeyFingerprint: invalid.signerFingerprint}).ok, false);
  }
  const other = openPgpFixture({subkeys: 1});
  assert.equal(validateCertificate(key.publicKey + other.publicKey, config).ok, false);
  assert.equal(validateCertificate('', config).ok, false);
  assert.equal(validateCertificate('x'.repeat(1024 * 1024 + 1), config).ok, false);
});
