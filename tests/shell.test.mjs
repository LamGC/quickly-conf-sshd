import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const candidates = [['POSIX sh', '/bin/sh'], ['bash POSIX mode', 'bash --posix'], ['BusyBox ash', 'busybox sh']];
for (const [label, shell] of candidates) {
  const executable = shell.split(' ')[0];
  const available = spawnSync(executable, executable === 'busybox' ? ['sh', '-c', ':'] : ['-c', ':']).status === 0;
  test(`isolated installer regression suite (${label})`, { skip: !available }, () => {
    const result = spawnSync('python3', ['tests/shell.test.py'], {
      cwd: root, encoding: 'utf8', timeout: 90_000,
      env: { ...process.env, CONF_SSHD_TEST_SHELL: shell },
    });
    assert.equal(result.error, undefined, result.error?.message);
    assert.equal(result.status, 0, result.stdout + result.stderr);
  });
}
test('ShellCheck POSIX diagnostics', { skip: spawnSync('shellcheck', ['--version']).status !== 0 }, () => {
  const result = spawnSync('shellcheck', ['--shell=sh', 'conf-sshd.sh'], { cwd: root, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stdout + result.stderr);
});
