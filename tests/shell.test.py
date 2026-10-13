#!/usr/bin/env python3
"""Installer integration tests. Every run uses a private HOME and mocked network/cron.
No SSH service, real account, real network, package manager, or production key is used.
"""
import hashlib
import base64
import struct
import signal
import os
import re
from pathlib import Path
import shutil
import shlex
import subprocess
import tempfile
import time
import unittest
import json
import pty
import select
import errno

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'conf-sshd.sh').read_text()
SHELL = shlex.split(os.environ.get('CONF_SSHD_TEST_SHELL', '/bin/sh'))
ORIGIN = 'https://keys.example.test'
SCRIPT = SOURCE.replace('@@BASE_URL@@', ORIGIN).replace('@@DEFAULT_CRON@@', '*/15 * * * *').replace('@@DEFAULT_GPG_VERIFY@@', 'off').replace('@@DEFAULT_GPG_FINGERPRINT@@', '').replace('@@DEFAULT_GPG_PIN_MODE@@', 'primary').replace('@@DEFAULT_LIST_ID@@', '').replace('@@DEFAULT_GPG_EMAIL@@', '')
KEY = (ROOT / 'tests/fixtures/keys.pub').read_bytes().strip() + b'\n'
BEGIN = b'# --- BEGIN MANAGED BY CONF-SSHD SCRIPT ---\n'
END = b'# --- END MANAGED BY CONF-SSHD SCRIPT ---\n'
CB = '# --- BEGIN CRON MANAGED BY CONF-SSHD SCRIPT ---\n'
CE = '# --- END CRON MANAGED BY CONF-SSHD SCRIPT ---\n'


def response(payload=KEY, allow='no', count=None):
    count = len(payload.splitlines()) if count is None else count
    return (f'# conf-sshd-v1\n# revision {"a" * 40}\n# key-count {count}\n'
            f'# allow-empty {allow}\n# sha256 {hashlib.sha256(payload).hexdigest()}\n'
            '# end-metadata\n').encode() + payload


class ShellTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='conf-sshd-tests-')
        self.root = Path(self.tmp.name)
        self.home = self.root / "home with 'quote"
        self.home.mkdir(mode=0o700)
        self.bin = self.root / 'bin'
        self.bin.mkdir(mode=0o700)
        self.script = self.root / 'installer.sh'
        self.script.write_text(SCRIPT)
        self.payload = self.root / 'response'
        self.payload.write_bytes(response())
        self.update = self.root / 'update'
        self.update.write_text(SCRIPT)
        self.cron = self.root / 'crontab'
        self.cron.write_text('MAILTO=admin@example.test\n17 * * * * echo untouched\n')
        self.calls = self.root / 'calls'
        self.calls.write_text('')
        self.env = dict(os.environ, HOME=str(self.home), PATH=f'{self.bin}:/usr/bin:/bin',
                        TEST_ROOT=str(self.root), TEST_RESPONSE=str(self.payload),
                        TEST_UPDATE=str(self.update), TEST_CRONTAB=str(self.cron),
                        TEST_CALLS=str(self.calls))
        real_id = shutil.which('id')
        self.assertIsNotNone(real_id)
        self.mock('id', f'#!/bin/sh\nexec {shlex.quote(real_id)} "$@"\n')
        self.mock('curl', '''#!/bin/sh
printf 'curl %s\\n' "$*" >> "$TEST_CALLS"
[ "${TEST_CURL_ERROR:-0}" = 0 ] || exit "$TEST_CURL_ERROR"
if [ "${TEST_CURL_WAIT:-0}" = 1 ]; then
    : > "$TEST_ROOT/waiting"
    while [ ! -f "$TEST_ROOT/release" ]; do sleep 0.02; done
fi
out=
while [ "$#" -gt 0 ]; do
    case "$1" in --output) shift; out=$1 ;; https://*) url=$1 ;; esac
    shift
done
status=${TEST_HTTP_STATUS:-200}
case $url in
    */script.sh) cp "$TEST_UPDATE" "$out" ;;
    */public-key.gpg) cp "${TEST_CERTIFICATE:-/nonexistent}" "$out" || exit 22; status=${TEST_CERT_STATUS:-$status} ;;
    */mirror/ssh.keys.sig) cp "${TEST_FALLBACK_SIGNATURE:-$TEST_SIGNATURE}" "$out"; status=${TEST_FALLBACK_SIG_STATUS:-$status} ;;
    */mirror/ssh.keys) cp "${TEST_FALLBACK_RESPONSE:-$TEST_RESPONSE}" "$out"; status=${TEST_FALLBACK_KEY_STATUS:-$status} ;;
    */ssh.keys.sig) cp "${TEST_SIGNATURE:-/nonexistent}" "$out" || exit 22; status=${TEST_SIG_STATUS:-$status} ;;
    */ssh.keys) cp "$TEST_RESPONSE" "$out"; status=${TEST_KEY_STATUS:-$status} ;;
    *) exit 99 ;;
esac
printf '%s' "$status"
''')
        self.mock('crontab', '''#!/bin/sh
printf 'crontab %s\\n' "$*" >> "$TEST_CALLS"
[ "${TEST_CRON_ERROR:-0}" = 0 ] || { echo 'permission denied' >&2; exit 1; }
if [ "$1" = -l ]; then
    if [ -f "$TEST_CRONTAB" ]; then cat "$TEST_CRONTAB"; else echo "no crontab for test-user" >&2; exit 1; fi
else
    [ "${TEST_CRON_WRITE_ERROR:-0}" = 0 ] || exit 1
    cp "$1" "$TEST_CRONTAB"
fi
''')
        for cmd in ('sshd', 'apt-get', 'yum', 'dnf', 'systemctl', 'service'):
            self.mock(cmd, f'#!/bin/sh\necho "UNEXPECTED {cmd} $*" >> "$TEST_CALLS"\nexit 98\n')

    def tearDown(self):
        self.tmp.cleanup()

    def mock(self, name, text):
        path = self.bin / name
        # Probes use invalid real-tool arguments, so a failed interception can
        # never mutate the actual account or crontab. Every mock answers before
        # its ordinary test-specific implementation runs.
        first, rest = text.split('\n', 1)
        text = (first + '\n'
                'if [ "${1-}" = --conf-sshd-isolation-probe ]; then\n'
                f'    printf \'%s\\n\' {shlex.quote("conf-sshd-mock:" + name)}\n'
                '    exit 0\n'
                'fi\n' + rest)
        path.write_text(text)
        path.chmod(0o700)
        return path

    def isolation_prelude(self):
        # BusyBox FEATURE_SH_STANDALONE may run applets before consulting PATH.
        # Shell functions take precedence over applets, and an absolute mock
        # path cannot resolve to an applet. Build fresh for every invocation so
        # test-specific id/stat/cp/cat/dd/mv mocks are intercepted as well.
        lines = []
        for path in sorted(self.bin.iterdir()):
            if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', path.name):
                lines.append(f'{path.name}() {{ {shlex.quote(str(path))} "$@"; }}')
            # Hyphenated command names such as apt-get are not POSIX function
            # identifiers and have no BusyBox applets; their PATH mocks remain.
        for name in ('id', 'crontab'):
            lines.extend([
                f'if [ "$({name} --conf-sshd-isolation-probe)" != conf-sshd-mock:{name} ]; then',
                f'    printf \'%s\\n\' \'TEST ISOLATION FAILED: {name} mock was bypassed\' >&2',
                '    exit 97',
                'fi',
            ])
        return '\n'.join(lines) + '\n'

    def script_command(self, *args, script=None):
        # Preserve the production script's arguments and $0 while loading it
        # in a shell whose command resolution has passed the isolation probes.
        return [*SHELL, '-c', self.isolation_prelude() + '. "$0"',
                str(script or self.script), *args]

    def run_script(self, *args, ok=True, env=None, script=None):
        completed = subprocess.run(self.script_command(*args, script=script),
                                   env=self.env | (env or {}), capture_output=True, text=True,
                                   timeout=15)
        if ok:
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        else:
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertNotIn('UNEXPECTED', self.calls.read_text())
        return completed

    @property
    def auth(self):
        return self.home / '.ssh/authorized_keys'

    @property
    def installed(self):
        return self.home / '.conf-sshd/conf-sshd.sh'

    def old_auth(self, data=b'# unmanaged\n'):
        self.auth.parent.mkdir(mode=0o700, exist_ok=True)
        self.auth.write_bytes(data)
        self.auth.chmod(0o600)
        return data

    def assert_clean(self):
        self.assertFalse((self.home / '.conf-sshd/lock').exists())
        self.assertEqual(list(self.home.glob('**/.conf-sshd.*')), [])

    def test_posix_parse_and_build_tokens_unique(self):
        self.assertEqual(SOURCE.count('@@BASE_URL@@'), 1)
        self.assertEqual(SOURCE.count('@@DEFAULT_CRON@@'), 1)
        subprocess.run([*SHELL, '-n', str(self.script)], check=True)

    def test_isolation_probe_aborts_before_installer_when_mock_is_bypassed(self):
        for name in ('id', 'crontab'):
            with self.subTest(name=name):
                mock_path = self.bin / name
                original = mock_path.read_text()
                try:
                    # Simulate a broken interception without calling real tools.
                    mock_path.write_text('#!/bin/sh\nprintf "wrong-tool\\n"\n')
                    result = self.run_script('-c', ok=False)
                    self.assertEqual(result.returncode, 97)
                    self.assertIn(f'TEST ISOLATION FAILED: {name}', result.stderr)
                    self.assertFalse((self.home / '.conf-sshd').exists())
                    self.assertFalse(self.auth.exists())
                    self.assertEqual(self.calls.read_text(), '')
                finally:
                    mock_path.write_text(original)

    def test_default_sync_has_no_system_or_cron_side_effects(self):
        old_cron = self.cron.read_bytes()
        self.run_script()
        self.assertEqual(self.auth.read_bytes(), BEGIN + KEY + END)
        self.assertEqual(self.cron.read_bytes(), old_cron)
        self.assertFalse(self.installed.exists())
        self.assertEqual(self.auth.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.auth.parent.stat().st_mode & 0o777, 0o700)
        self.assert_clean()

    def test_unmanaged_no_final_newline_is_not_lost(self):
        original = self.old_auth(b'command="echo keep",no-pty ssh-ed25519 LOCAL user')
        self.run_script('-o')
        self.assertEqual(self.auth.read_bytes(), original + b'\n' + BEGIN + KEY + END)
        self.assertEqual(Path(str(self.auth) + '.conf-sshd.bak').read_bytes(), original)

    def test_existing_block_preserves_unmanaged_bytes_and_final_no_newline(self):
        prefix = b'# first\nssh-rsa unmanaged-prefix\n'
        suffix = b'command="keep" ssh-rsa unmanaged-suffix'
        self.old_auth(prefix + BEGIN + b'old-managed\n' + END + suffix)
        self.run_script('-o')
        self.assertEqual(self.auth.read_bytes(), prefix + BEGIN + KEY + END + suffix)

    def test_idempotent_sync_and_bounded_backup(self):
        original = self.old_auth()
        self.run_script('-o')
        before = self.auth.read_bytes()
        self.run_script('-o')
        self.assertEqual(self.auth.read_bytes(), before)
        self.assertEqual(Path(str(self.auth) + '.conf-sshd.bak').read_bytes(), original)
        self.assertEqual(len(list(self.auth.parent.glob('*.bak'))), 1)
        self.assert_clean()

    def test_marker_corruption_fails_closed(self):
        cases = [BEGIN, END, END + BEGIN, BEGIN + BEGIN + END, BEGIN + END + BEGIN + END,
                 BEGIN[:-1] + b' extra\n' + END, BEGIN + END[:-1] + b' extra\n']
        for original in cases:
            with self.subTest(original=original):
                self.old_auth(original)
                self.run_script('-o', ok=False)
                self.assertEqual(self.auth.read_bytes(), original)
                self.assert_clean()

    def test_http_errors_keep_last_good_and_cleanup(self):
        original = self.old_auth()
        for error in ('22', '28', '6', '60'):
            with self.subTest(error=error):
                self.run_script('-o', ok=False, env={'TEST_CURL_ERROR': error})
                self.assertEqual(self.auth.read_bytes(), original)
                self.assert_clean()
        calls = self.calls.read_text()
        for option in ('--disable', '--fail', '--proto =https', '--connect-timeout 10', '--max-time 30', '--retry 0'):
            self.assertIn(option, calls)
        self.assertNotIn('--location', calls)

    def test_empty_set_requires_explicit_permission(self):
        original = self.old_auth(BEGIN + KEY + END + b'# keep\n')
        self.payload.write_bytes(response(b''))
        self.run_script('-o', ok=False)
        self.assertEqual(self.auth.read_bytes(), original)
        self.payload.write_bytes(response(b'', allow='yes'))
        self.run_script('-o')
        self.assertEqual(self.auth.read_bytes(), BEGIN + END + b'# keep\n')

    def test_metadata_and_payload_corruption(self):
        original = self.old_auth()
        good = response()
        cases = [good[:-1], good.replace(b'# conf-sshd-v1', b'# conf-sshd-v2'),
                 good.replace(b'# key-count 1', b'# key-count 01'),
                 good.replace(b'# key-count 1', b'# key-count 2'),
                 good.replace(b'# allow-empty no', b'# allow-empty maybe'),
                 good.replace(b'# revision ' + b'a' * 40, b'# revision ' + b'a' * 39),
                 good.replace(b'# end-metadata', b'# extra\n# end-metadata'),
                 good.replace(b'AAAAC', b'BAAAC'), good.replace(b'\n', b'\r\n'),
                 response(KEY + b'\x00\n'), response(b'\n')]
        for value in cases:
            with self.subTest(value=value[:70]):
                self.payload.write_bytes(value)
                self.run_script('-o', ok=False)
                self.assertEqual(self.auth.read_bytes(), original)
                self.assert_clean()

    def test_duplicate_option_malformed_and_unsupported_keys(self):
        original = self.old_auth()
        no_comment = b' '.join(KEY.split()[:2])
        cases = [KEY + KEY, KEY + no_comment + b' changed-comment\n',
                 b'command="id" ' + KEY, b'ssh-rsa AAAA bad\n',
                 KEY.replace(b'ssh-ed25519 ', b'ssh-rsa '),
                 KEY.replace(b' ', b'  ', 1), KEY.rstrip() + b' \n',
                 KEY.replace(b'ssh-ed25519', b'ssh-dss'),
                 KEY.replace(b'ssh-ed25519', b'ssh-ed25519-cert-v01@openssh.com')]
        for value in cases:
            with self.subTest(value=value[:70]):
                self.payload.write_bytes(response(value))
                self.run_script('-o', ok=False)
                self.assertEqual(self.auth.read_bytes(), original)
        self.assert_clean()

    def test_printable_comments_can_contain_spaces_and_symbols(self):
        payload = b' '.join(KEY.split()[:2]) + ' 中文 comment with  spaces $;# ! \'"\n'.encode()
        self.payload.write_bytes(response(payload))
        self.run_script('-o')
        self.assertEqual(self.auth.read_bytes(), BEGIN + payload + END)

    def test_synthetic_rsa_and_ecdsa_and_weak_rsa(self):
        for kind, bits in [('rsa', 2048), ('ecdsa', 256), ('ecdsa', 384), ('ecdsa', 521), ('rsa', 1024)]:
            with self.subTest(kind=kind, bits=bits):
                keyfile = self.root / 'ephemeral-test-key'
                subprocess.run(['ssh-keygen', '-q', '-t', kind, '-b', str(bits), '-N', '', '-f', str(keyfile)], check=True)
                payload = keyfile.with_suffix('.pub').read_bytes()
                keyfile.unlink()  # Never retained or installed; fixture public key only.
                keyfile.with_suffix('.pub').unlink()
                self.payload.write_bytes(response(payload))
                self.run_script('-o', ok=(bits != 1024))
        self.assert_clean()

    def test_symlink_auth_ssh_home_and_backup_are_rejected(self):
        outside = self.root / 'outside'
        outside.write_bytes(b'untouched')
        self.auth.parent.mkdir(mode=0o700)
        self.auth.symlink_to(outside)
        self.run_script('-o', ok=False)
        self.assertEqual(outside.read_bytes(), b'untouched')
        self.auth.unlink()
        self.old_auth()
        backup = Path(str(self.auth) + '.conf-sshd.bak')
        backup.symlink_to(outside)
        original = self.auth.read_bytes()
        self.run_script('-o', ok=False)
        self.assertEqual(self.auth.read_bytes(), original)
        backup.unlink()
        self.auth.unlink()
        self.auth.parent.rmdir()
        self.auth.parent.symlink_to(self.root, target_is_directory=True)
        self.run_script('-o', ok=False)
        linked_home = self.root / 'linked-home'
        linked_home.symlink_to(self.home, target_is_directory=True)
        self.run_script('-o', ok=False, env={'HOME': str(linked_home)})

    def test_group_writable_and_hardlinked_files_are_rejected(self):
        original = self.old_auth()
        self.auth.chmod(0o666)
        self.run_script('-o', ok=False)
        self.assertEqual(self.auth.read_bytes(), original)
        self.auth.chmod(0o600)
        os.link(self.auth, self.root / 'hardlink')
        self.run_script('-o', ok=False)
        self.assertEqual(self.auth.read_bytes(), original)

    def test_unicode_home_path_is_safe(self):
        unicode_home = self.root / '测试 home'
        unicode_home.mkdir(mode=0o700)
        self.run_script('-c', env={'HOME': str(unicode_home)})
        self.assertEqual((unicode_home / '.ssh/authorized_keys').read_bytes(), BEGIN + KEY + END)
        self.assertIn(str(unicode_home), self.cron.read_text())

    def test_home_control_characters_rejected_before_writes(self):
        for suffix in ['\ninside', '\n', '\r', '\t', '\\literal']:
            with self.subTest(suffix=repr(suffix)):
                unsafe_home = self.root / ('unsafe' + suffix)
                unsafe_home.mkdir(mode=0o700)
                self.run_script('-o', ok=False, env={'HOME': str(unsafe_home)})
                self.assertEqual(list(unsafe_home.iterdir()), [])

    def test_wrong_owner_is_rejected(self):
        real_stat = shutil.which('stat')
        self.mock('stat', f'''#!/bin/sh
"{real_stat}" "$@" | sed 's/^[0-9][0-9]*/99999/'
''')
        self.run_script('-o', ok=False)
        self.assertFalse(self.auth.exists())

    def test_cron_bare_default_custom_preservation_and_safe_quotes(self):
        unrelated = self.cron.read_text()
        self.run_script('-c')
        text = self.cron.read_text()
        self.assertTrue(text.startswith(unrelated))
        self.assertIn("*/15 * * * * /bin/sh '", text)
        self.assertIn("'\\''quote/.conf-sshd/conf-sshd.sh' -o", text)
        self.assertNotRegex(text, r'(?:^|\s)-u(?:\s|$)')
        self.assertEqual(self.installed.stat().st_mode & 0o777, 0o700)
        text = text.replace('*/15 * * * *', '7 1 * * 2')
        self.cron.write_text(text)
        self.run_script('-c')
        self.assertEqual(self.cron.read_text(), text)
        self.run_script('-c', '*/10 2-8/2 * 1,6 0-7')
        self.assertIn('*/10 2-8/2 * 1,6 0-7 /bin/sh', self.cron.read_text())
        self.run_script('-c', 'false', env={'TEST_CURL_ERROR': '22'})
        self.assertEqual(self.cron.read_text(), unrelated)
        self.assert_clean()

    def test_cron_legacy_migrates_custom_schedule_only_exact_target(self):
        unrelated = '5 * * * * /bin/sh /other/conf-sshd.sh -o\n# conf-sshd.sh note\n'
        legacy = f'3 4 * * 1 "/bin/bash {self.installed} -o" >> {self.home}/.conf-sshd/run.log 2>&1\n'
        self.cron.write_text(unrelated + legacy)
        self.run_script('-c')
        text = self.cron.read_text()
        self.assertTrue(text.startswith(unrelated))
        self.assertIn('3 4 * * 1 /bin/sh', text)
        self.assertNotIn('"/bin/bash', text)
        self.assertEqual(text.count(CB), 1)

    def test_cron_errors_and_bad_managed_markers_do_not_clobber(self):
        cases = [CB, CE, CB + CE, CB + '* * * * * unknown command\n' + CE,
                 CB + CE + CB + CE]
        for text in cases:
            with self.subTest(text=text):
                self.cron.write_text(text)
                self.run_script('-c', ok=False)
                self.assertEqual(self.cron.read_text(), text)
                self.assertFalse(self.auth.exists())
                self.assert_clean()
        original = self.cron.read_bytes()
        self.run_script('-c', ok=False, env={'TEST_CRON_ERROR': '1'})
        self.assertEqual(self.cron.read_bytes(), original)

    def test_cron_no_existing_crontab(self):
        self.cron.unlink()
        self.run_script('-c')
        self.assertIn('*/15 * * * *', self.cron.read_text())

    def test_cron_expression_rejects_injection_ranges_and_missing_fields(self):
        cases = ['* * * *', '60 * * * *', '* 24 * * *', '* * 0 * *', '* * * 13 *',
                 '* * * * 8', '*/0 * * * *', '10-2 * * * *', '@daily',
                 '* * * * *; touch /tmp/bad', '* * * * *\n* * * * *', '* * * * *%id']
        original = self.cron.read_bytes()
        for value in cases:
            with self.subTest(value=value):
                self.run_script('-c', value, ok=False)
                self.assertEqual(self.cron.read_bytes(), original)
                self.assertFalse(self.auth.exists())

    def test_argument_conflicts_missing_values_unknown(self):
        for args in [('-u', '-o'), ('-o', '-c'), ('-p',), ('-p', 'maybe'),
                     ('--uninstall', '-c'), ('-c', '-c'), ('--unknown',),
                     ('-c', ''), ('--dry-run', '--dry-run'), ('--status', '-c')]:
            with self.subTest(args=args):
                self.run_script(*args, ok=False)
                self.assertFalse(self.auth.exists())

    def test_dry_run_no_persistent_changes(self):
        old_cron = self.cron.read_bytes()
        self.run_script('-c', '--dry-run')
        self.assertFalse(self.auth.exists())
        self.assertFalse(self.installed.exists())
        self.assertEqual(self.cron.read_bytes(), old_cron)
        self.assertFalse((self.home / '.ssh').exists())
        self.assertFalse((self.home / '.conf-sshd').exists())
        self.old_auth()
        state = self.home / '.conf-sshd'
        state.mkdir(mode=0o755)
        self.run_script('-o', '--dry-run')
        self.assertEqual(state.stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.auth.read_bytes(), b'# unmanaged\n')

    def test_concurrent_run_refuses_and_signal_cleanup(self):
        env = self.env | {'TEST_CURL_WAIT': '1'}
        first = subprocess.Popen(self.script_command('-o'), env=env,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while not (self.root / 'waiting').exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue((self.root / 'waiting').exists())
            completed = self.run_script('-o', ok=False)
            self.assertIn('Another run holds', completed.stderr)
            (self.root / 'release').touch()
            stdout, stderr = first.communicate(timeout=10)
            self.assertEqual(first.returncode, 0, stdout + stderr)
        finally:
            if first.poll() is None:
                (self.root / 'release').touch()
                first.terminate()
                first.communicate(timeout=10)
        self.assert_clean()
        # A stale/foreign lock is never auto-removed.
        lock = self.home / '.conf-sshd/lock'
        lock.mkdir()
        (lock / 'pid').write_text('999999')
        self.run_script('-o', ok=False)
        self.assertTrue(lock.exists())

    def test_update_self_is_explicit_atomic_and_fail_closed(self):
        self.run_script('-c')
        original = self.installed.read_bytes()
        keys = self.auth.read_bytes()
        cron = self.cron.read_bytes()
        cases = ['#!/bin/sh\necho invalid\n', SCRIPT + '\nif\n',
                 SCRIPT.replace('# conf-sshd-script-v2', '# other'),
                 SCRIPT.replace(ORIGIN, 'https://different.example.test'),
                 SCRIPT + '\n# conf-sshd-script-v2\n', SCRIPT + '\n# @@UNBUILT@@\n']
        for text in cases:
            with self.subTest(text=text[:40]):
                self.update.write_text(text)
                self.run_script('--install', '--download-script', ok=False)
                self.assertEqual(self.installed.read_bytes(), original)
                self.assert_clean()
        self.run_script('--install', '--download-script', ok=False, env={'TEST_CURL_ERROR': '22'})
        self.update.write_text(SCRIPT + '\n# new release\n')
        self.run_script('--install', '--download-script')
        self.assertEqual(self.installed.read_bytes(), self.update.read_bytes())
        self.assertEqual(Path(str(self.installed) + '.conf-sshd.bak').read_bytes(), original)
        self.assertEqual(self.auth.read_bytes(), keys)
        self.assertEqual(self.cron.read_bytes(), cron)
        self.assert_clean()

    def test_update_without_install_fails(self):
        self.run_script('-u', ok=False)
        self.assertFalse(self.installed.exists())

    def test_uninstall_preserves_keys_unrelated_files_and_cron(self):
        original_cron = self.cron.read_text()
        self.run_script('-c')
        original_keys = self.auth.read_bytes()
        keep = self.home / '.conf-sshd/keep-user-file'
        keep.write_text('keep')
        self.run_script('--uninstall')
        self.assertEqual(self.auth.read_bytes(), original_keys)
        self.assertEqual(self.cron.read_text(), original_cron)
        self.assertFalse(self.installed.exists())
        self.assertEqual(keep.read_text(), 'keep')
        self.assert_clean()

    def test_root_policy_requires_root_without_touching_sshd(self):
        if os.getuid() == 0:
            self.skipTest('Non-root refusal test requires an unprivileged test runner.')
        result = self.run_script('-p', 'no', ok=False)
        self.assertIn('requires root', result.stderr)

    def mock_root_config(self, text='Port 2222\n# preserve comment\nPermitRootLogin no\n'):
        config_dir = self.root / 'fake-etc-ssh'
        config_dir.mkdir(mode=0o700, exist_ok=True)
        config = config_dir / 'sshd_config'
        config.write_text(text)
        config.chmod(0o600)
        # Rewrite fixture copy only; the shipped script has no environment override.
        fixture = SCRIPT.replace('config=/etc/ssh/sshd_config', f"config='{config}'")
        fixture = fixture.replace('check_path /etc/ssh dir', f"check_path '{config_dir}' dir")
        fixture = fixture.replace('new_temp /etc/ssh;', f"new_temp '{config_dir}';")
        self.assertNotIn('/etc/ssh', fixture, 'All root-policy paths must stay inside test fixtures')
        self.script.write_text(fixture)
        self.mock('id', '#!/bin/sh\nprintf "0\\n"\n')
        real_stat = shutil.which('stat')
        self.mock('stat', f'#!/bin/sh\n"{real_stat}" "$@" | sed \'s/^[0-9][0-9]*/0/\'\n')
        self.mock('sshd', '''#!/bin/sh
printf 'sshd %s\\n' "$*" >> "$TEST_CALLS"
operation=$1
shift
[ "$1" = -f ] || exit 90
config=$2
[ "${TEST_SSHD_FAIL:-}" != "$operation" ] || exit 1
if [ "$operation" = -T ]; then
    if [ "${TEST_SSHD_OVERRIDE:-0}" = 1 ]; then echo 'permitrootlogin no'
    else awk 'tolower($1)=="permitrootlogin" {print "permitrootlogin " $2; exit}' "$config"; fi
fi
''')
        return config

    def test_key_comment_marker_phrase_can_sync_and_revoke(self):
        payload = b' '.join(KEY.split()[:2]) + b' MANAGED BY CONF-SSHD SCRIPT\n'
        self.payload.write_bytes(response(payload))
        self.run_script('-o')
        self.run_script('-o')
        self.payload.write_bytes(response(b'', allow='yes'))
        self.run_script('-o')
        self.assertEqual(self.auth.read_bytes(), BEGIN + END)

    def test_external_authorized_keys_edit_during_backup_is_not_overwritten(self):
        original = self.old_auth(b'# original user key\n')
        real_cp = shutil.which('cp')
        self.mock('cp', f'''#!/bin/sh
"{real_cp}" "$@" || exit $?
case "$1:$2" in "$HOME/.ssh/authorized_keys:$HOME/.ssh/.conf-sshd."*)
    printf '# concurrent manual key\\n' >> "$HOME/.ssh/authorized_keys" ;;
esac
''')
        result = self.run_script('-o', ok=False)
        self.assertIn('changed concurrently', result.stderr)
        self.assertEqual(self.auth.read_bytes(), original + b'# concurrent manual key\n')
        self.assertFalse(Path(str(self.auth) + '.conf-sshd.bak').exists())
        self.assert_clean()

    def test_new_authorized_keys_created_concurrently_is_preserved(self):
        real_cat = shutil.which('cat')
        self.mock('cat', f'''#!/bin/sh
"{real_cat}" "$@" || exit $?
if [ "$#" = 1 ] && [ -f "$1" ] && grep -q '^ssh-ed25519 ' "$1"; then
    if [ ! -e "$HOME/.ssh/authorized_keys" ]; then
        printf '# concurrently created user key\\n' > "$HOME/.ssh/authorized_keys"
    fi
fi
''')
        result = self.run_script('-o', ok=False)
        self.assertIn('appeared concurrently', result.stderr)
        self.assertEqual(self.auth.read_bytes(), b'# concurrently created user key\n')
        self.assert_clean()

    def test_piped_install_ignores_same_named_unrelated_cwd_file(self):
        decoy = self.root / 'sh'
        decoy.write_text(SCRIPT + '\n# UNTRUSTED CWD DECOY\n')
        completed = subprocess.run([*SHELL, '-s', '--', '-c'], input=self.isolation_prelude() + SCRIPT,
                                   cwd=self.root, env=self.env, capture_output=True, text=True, timeout=15)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertNotIn('UNTRUSTED CWD DECOY', self.installed.read_text())
        self.assertEqual(self.installed.read_text(), SCRIPT)
        self.assertIn('/script.sh', self.calls.read_text())
        self.assert_clean()

    def test_root_policy_staged_validation_backup_no_reload(self):
        config = self.mock_root_config('Port 2222\n# preserve comment\nPermitRootLogin=no\n"PermitRootLogin" no\n')
        original = config.read_bytes()
        self.run_script('-p', 'no')
        self.assertTrue(config.read_text().startswith('PermitRootLogin prohibit-password\n'))
        self.assertIn('Port 2222\n# preserve comment\n', config.read_text())
        self.assertEqual(Path(str(config) + '.conf-sshd.bak').read_bytes(), original)
        self.assertEqual(config.read_text().count('PermitRootLogin'), 1)
        self.run_script('-p', 'yes')
        self.assertTrue(config.read_text().startswith('PermitRootLogin yes\n'))
        self.assertIn('sshd -t -f', self.calls.read_text())
        self.assertIn('sshd -T -f', self.calls.read_text())
        self.assertFalse(self.auth.exists())
        self.assert_clean()
        self.assertEqual(list(config.parent.glob('.conf-sshd.*')), [])

    def test_root_policy_include_match_invalid_effective_and_dry_run(self):
        config = self.mock_root_config()
        for text in ['Include sshd_config.d/*.conf\n', ' Match User test\n',
                     'Port 2222\nINCLUDE other\n', 'mAtCh all\n',
                     'Include=other\n', 'Match=User root\n', '"Include"=other\n',
                     '"Match" User root\n', '"Match"User root\n']:
            with self.subTest(text=text):
                config.write_text(text)
                self.run_script('-p', 'no', ok=False)
                self.assertEqual(config.read_text(), text)
        config.write_text('PermitRootLogin no\n# unchanged\n')
        original = config.read_bytes()
        for env in [{'TEST_SSHD_FAIL': '-t'}, {'TEST_SSHD_FAIL': '-T'}, {'TEST_SSHD_OVERRIDE': '1'}]:
            self.run_script('-p', 'yes', ok=False, env=env)
            self.assertEqual(config.read_bytes(), original)
            self.assertFalse(Path(str(config) + '.conf-sshd.bak').exists())
            self.assert_clean()
        self.run_script('-p', 'yes', '--dry-run')
        self.assertEqual(config.read_bytes(), original)
        self.assertEqual(list(config.parent.glob('.conf-sshd.*')), [])

    def test_security_key_public_blob_and_canonical_base64(self):
        def sshstring(value):
            return struct.pack('>I', len(value)) + value
        public = base64.b64decode(KEY.split()[1])[-32:]
        kind = b'sk-ssh-ed25519@openssh.com'
        blob = sshstring(kind) + sshstring(public) + sshstring(b'ssh:fixturex')
        payload = kind + b' ' + base64.b64encode(blob) + b' public-fixture-only\n'
        self.payload.write_bytes(response(payload))
        self.run_script('-o')
        original = self.auth.read_bytes()
        # Different non-zero padding bits can decode to the same byte string.
        padded = base64.b64encode(blob)
        self.assertTrue(padded.endswith(b'='))
        alphabet = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        offset = -3 if padded.endswith(b'==') else -2
        altered = bytearray(padded)
        altered[offset] = alphabet[alphabet.index(altered[offset]) + 1]
        invalid = kind + b' ' + bytes(altered) + b' invalid-padding\n'
        self.payload.write_bytes(response(invalid))
        self.run_script('-o', ok=False)
        self.assertEqual(self.auth.read_bytes(), original)
        # Build an SK-ECDSA public fixture from a transient ordinary ECDSA key.
        keyfile = self.root / 'ephemeral-ecdsa'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ecdsa', '-b', '256', '-N', '', '-f', str(keyfile)], check=True)
        ec = base64.b64decode(keyfile.with_suffix('.pub').read_bytes().split()[1])
        keyfile.unlink()
        keyfile.with_suffix('.pub').unlink()
        kind = b'sk-ecdsa-sha2-nistp256@openssh.com'
        old_type_len = struct.unpack('>I', ec[:4])[0]
        blob = sshstring(kind) + ec[4 + old_type_len:] + sshstring(b'ssh:test-only')
        payload = kind + b' ' + base64.b64encode(blob) + b' synthetic-security-key\n'
        self.payload.write_bytes(response(payload))
        self.run_script('-o')

    def test_custom_build_default_and_update_preserve_configuration(self):
        custom = SCRIPT.replace("DEFAULT_CRON='*/15 * * * *'", "DEFAULT_CRON='8 3 * * *'")
        self.script.write_text(custom)
        self.update.write_text(custom)
        self.run_script('-c')
        self.assertIn('8 3 * * * /bin/sh', self.cron.read_text())
        self.update.write_text(custom + '\n# updated\n')
        self.run_script('--install', '--download-script')
        self.update.write_text(SCRIPT)
        self.run_script('--install', '--download-script', ok=False)

    def test_signal_removes_own_lock_and_temporary_files(self):
        first = subprocess.Popen(self.script_command('-o'),
                                 env=self.env | {'TEST_CURL_WAIT': '1'},
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                 start_new_session=True)
        try:
            deadline = time.monotonic() + 5
            while not (self.root / 'waiting').exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue((self.root / 'waiting').exists())
            os.killpg(first.pid, signal.SIGTERM)
            first.communicate(timeout=10)
            self.assertNotEqual(first.returncode, 0)
            self.assert_clean()
            self.assertFalse(self.auth.exists())
        finally:
            if first.poll() is None:
                os.killpg(first.pid, signal.SIGKILL)
                first.communicate(timeout=10)

    def test_concurrent_external_cron_edit_is_not_overwritten(self):
        self.mock('crontab', '''#!/bin/sh
if [ "$1" = -l ]; then
    if [ -f "$TEST_ROOT/cron-read" ]; then
        printf '42 * * * * echo concurrent-editor\\n' >> "$TEST_CRONTAB"
    fi
    touch "$TEST_ROOT/cron-read"
    cat "$TEST_CRONTAB"
else
    echo 'UNEXPECTED overwrote concurrent cron' >> "$TEST_CALLS"
    exit 98
fi
''')
        self.run_script('-c', ok=False)
        self.assertIn('concurrent-editor', self.cron.read_text())
        self.assertNotIn(CB, self.cron.read_text())
        self.assert_clean()

    def test_help_status_and_unbuilt_source(self):
        self.run_script('--help')
        self.run_script('--status')
        self.cron.unlink()
        self.run_script('--status')
        self.assertFalse((self.home / '.conf-sshd').exists())
        self.script.write_text(SOURCE)
        self.run_script('-o', ok=False)
        self.assertFalse(self.auth.exists())


class SignatureTests(ShellTests):
    """Pure sandbox OpenPGP/TTY fixtures; all network paths intercepted."""
    @classmethod
    def setUpClass(cls):
        cls.fixture_dir = tempfile.TemporaryDirectory(prefix='conf-sshd-gpg-fixtures-')
        js = r"""
import {openPgpFixture} from './tests/helpers/openpgp-fixture.mjs';
import {readFileSync} from 'node:fs';
const f = openPgpFixture({subkeys:2}), other = openPgpFixture(), expired = openPgpFixture({expired:true}), revoked = openPgpFixture({revoked:true});
const key=readFileSync('tests/fixtures/keys.pub','utf8').trim().split(/\s+/).slice(0,2).join(' ')+'\n';
const now=Math.floor(Date.now()/1000);
function doc({seq=5,list='fixture-list',issued=now-10,expires=now+3600,payload=key,revoke='no'}={}) {
  return `# conf-sshd-signed-v1\n# list-id ${list}\n# sequence ${seq}\n# issued-at ${issued}\n# expires-at ${expires}\n# revoke ${revoke}\n# key-count ${payload ? payload.trim().split('\n').length : 0}\n# end-metadata\n${payload}`;
}
const specs={good:{},next:{seq:6},later:{seq:7,expires:now+7200},old:{seq:4},equivocation:{issued:now-9},expired:{seq:6,issued:now-3600,expires:now-1},future:{seq:6,issued:now+3600,expires:now+7200},wronglist:{seq:6,list:'another'},revoke:{seq:6,payload:'',revoke:'yes'},badrevoke:{seq:6,revoke:'yes'},comment:{seq:6,payload:key.trim()+' comment\n'}};
const releases={}; for(const [name,spec] of Object.entries(specs)){const data=doc(spec);releases[name]={data,sig:f.sign(data)}}
releases.sibling={data:doc({seq:6}),sig:f.sign(doc({seq:6}),1)};
releases.textmode={data:doc({seq:6}),sig:f.signText(doc({seq:6}))};
releases.wrongsigner={data:doc({seq:6}),sig:other.sign(doc({seq:6}))};
console.log(JSON.stringify({publicKey:f.publicKey,primary:f.primaryFingerprint,subkeys:f.signerFingerprints,otherKey:other.publicKey,otherPin:other.primaryFingerprint,otherSig:other.sign(doc({seq:6})),expiredKey:expired.publicKey,expiredPin:expired.primaryFingerprint,expiredSig:expired.sign(doc()),revokedKey:revoked.publicKey,revokedPin:revoked.primaryFingerprint,revokedSig:revoked.sign(doc()),releases}));
"""
        generated = subprocess.run(['node', '--input-type=module', '-e', js], cwd=ROOT,
                                   check=True, capture_output=True, text=True)
        cls.fixtures = json.loads(generated.stdout)

    @classmethod
    def tearDownClass(cls):
        cls.fixture_dir.cleanup()

    def setUp(self):
        super().setUp()
        self.cert = self.root / 'public-key.gpg'
        self.cert.write_text(self.fixtures['publicKey'])
        self.signature = self.root / 'ssh.keys.sig'
        self.env.update(TEST_CERTIFICATE=str(self.cert), TEST_SIGNATURE=str(self.signature),
                        GNUPGHOME=str(self.root / 'empty-ambient-home'))
        self.set_release('good')
        real_gpg = shutil.which('gpg')
        self.assertIsNotNone(real_gpg)
        # GnuPG cryptographic work is real. Remote GnuPG discovery never is.
        self.mock('gpg', f'''#!/bin/sh
printf 'gpg %s\\n' "$*" >> "$TEST_CALLS"
home=; server=; action=
prev=
for arg do
    case $prev in --homedir) home=$arg ;; --keyserver) server=$arg ;; esac
    case $arg in --recv-keys|--locate-external-keys) action=$arg ;; esac
    prev=$arg
done
if [ -n "$action" ]; then
    if [ "${{TEST_DISCOVERY_SUCCESS:-}}" = "$server" ] || {{ [ "$action" = --locate-external-keys ] && [ "${{TEST_DISCOVERY_SUCCESS:-}}" = wkd ]; }}; then
        "{real_gpg}" --batch --no-options --no-autostart --yes --dearmor --output "$home/pubring.gpg" "$TEST_CERTIFICATE" 2>/dev/null
        exit $?
    fi
    exit 1
fi
exec "{real_gpg}" "$@"
''')

    def set_release(self, name):
        value = self.fixtures['releases'][name]
        self.payload.write_text(value['data'])
        self.signature.write_text(value['sig'])

    def run_tty(self, *args, answer=None, ok=True, env=None, script=None):
        command = self.script_command(*args, script=script)
        pid, fd = pty.fork()
        if pid == 0:
            os.execvpe(command[0], command, self.env | (env or {}))
        output = bytearray()
        sent = False
        deadline = time.monotonic() + 20
        code = None
        try:
            while time.monotonic() < deadline:
                ready, _, _ = select.select([fd], [], [], 0.05)
                if ready:
                    try:
                        data = os.read(fd, 65536)
                    except OSError as e:
                        if e.errno != errno.EIO:
                            raise
                        data = b''
                    output.extend(data)
                if not sent and b'To confirm ' in output:
                    os.write(fd, ((answer if answer is not None else self.fixtures['primary']) + '\n').encode())
                    sent = True
                result, status = os.waitpid(pid, os.WNOHANG)
                if result:
                    code = os.waitstatus_to_exitcode(status)
                    break
            if code is None:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
                self.fail('TTY fixture timed out: ' + output.decode(errors='replace'))
        finally:
            os.close(fd)
        result = output.decode(errors='replace')
        if ok:
            self.assertEqual(code, 0, result)
        else:
            self.assertNotEqual(code, 0, result)
        self.assertNotIn('UNEXPECTED', self.calls.read_text())
        return result

    def enroll(self, pin=None, mode='primary', extra=(), answer=None, ok=True):
        pin = pin or self.fixtures['primary']
        return self.run_tty('--install', '--gpg-verification', 'on', '--gpg-fingerprint', pin,
                            '--gpg-pin-mode', mode, '--list-id', 'fixture-list', *extra,
                            answer=answer or pin, ok=ok)

    @property
    def local_config(self):
        return self.home / '.conf-sshd/local.conf'

    @property
    def replay(self):
        return self.home / '.conf-sshd/replay.state'

    def test_strict_primary_accepts_bound_subkeys_and_sync_is_offline_for_certificate(self):
        self.enroll()
        self.assertIn('policy required\n', self.local_config.read_text())
        self.assertIn('sequence 5\n', self.replay.read_text())
        self.assertEqual(self.auth.read_bytes(), BEGIN + b' '.join(KEY.split()[:2]) + b'\n' + END)
        self.calls.write_text('')
        self.set_release('sibling')
        self.run_script('-o')
        calls = self.calls.read_text()
        self.assertIn('/ssh.keys.sig', calls)
        self.assertNotIn('/public-key.gpg', calls)
        self.assertNotIn('--recv-keys', calls)
        self.assertNotIn('--locate-external-keys', calls)
        self.assert_clean()

    def test_strict_exact_subkey_rejects_sibling_and_other_signer(self):
        self.enroll(pin=self.fixtures['subkeys'][0], mode='subkey')
        original = self.auth.read_bytes()
        for name in ('sibling', 'wrongsigner'):
            self.set_release(name)
            self.run_script('-o', ok=False)
            self.assertEqual(self.auth.read_bytes(), original)
        self.assert_clean()

    def test_strict_rejects_rollback_equivocation_expiry_future_wronglist_and_unsigned(self):
        self.enroll()
        original = self.auth.read_bytes()
        original_state = self.replay.read_bytes()
        for name in ('old', 'equivocation', 'expired', 'future', 'wronglist', 'badrevoke', 'comment', 'wrongsigner', 'textmode'):
            with self.subTest(name=name):
                self.set_release(name)
                self.run_script('-o', ok=False)
                self.assertEqual(self.auth.read_bytes(), original)
                self.assertEqual(self.replay.read_bytes(), original_state)
                self.assert_clean()
        self.payload.write_bytes(response())
        self.signature.write_text('')
        self.run_script('-o', ok=False)
        self.assertEqual(self.auth.read_bytes(), original)

    def test_strict_idempotent_replay_and_explicit_empty_revocation(self):
        original = self.old_auth(b'# manual recovery key\n')
        self.enroll()
        self.run_script('-o')
        self.set_release('revoke')
        self.run_script('-o')
        self.assertEqual(self.auth.read_bytes(), original + BEGIN + END)
        self.assertIn('sequence 6\n', self.replay.read_text())
        self.set_release('good')
        self.run_script('-o', ok=False)
        self.assertEqual(self.auth.read_bytes(), original + BEGIN + END)

    def test_off_never_requests_signature_or_certificate_even_when_present(self):
        self.signature.write_text('definitely invalid')
        self.run_script('-o')
        self.assertNotIn('/ssh.keys.sig', self.calls.read_text())
        self.assertNotIn('/public-key.gpg', self.calls.read_text())
        self.assertNotIn('gpg ', self.calls.read_text())
        self.assertFalse(self.replay.exists())

    def test_signature_requires_exact_http_200_and_exact_bytes(self):
        self.enroll()
        original = self.auth.read_bytes()
        for status in ('201', '204', '206', '301', '404', '503'):
            for key in ('TEST_KEY_STATUS', 'TEST_SIG_STATUS'):
                with self.subTest(status=status, part=key):
                    self.run_script('-o', ok=False, env={key:status})
                    self.assertEqual(self.auth.read_bytes(), original)
        self.payload.write_text(self.payload.read_text().replace('sequence 5', 'sequence 6'))
        self.run_script('-o', ok=False)
        self.assertEqual(self.auth.read_bytes(), original)

    def test_cancel_no_tty_and_removed_bypass_preserve_targets_without_network(self):
        original = self.old_auth()
        self.enroll(answer='cancel', ok=False)
        self.assertFalse(self.local_config.exists())
        self.assertFalse(self.installed.exists())
        self.assertEqual(self.auth.read_bytes(), original)
        self.assertEqual(self.calls.read_text(), '')
        self.run_script('--install', '--gpg-verification', 'on', '--gpg-fingerprint', self.fixtures['primary'], '--list-id', 'fixture-list', ok=False)
        self.assertEqual(self.calls.read_text(), '')
        self.run_script('--install', '--confirm-trust', self.fixtures['primary'], ok=False)
        self.assertEqual(self.calls.read_text(), '')
        self.assert_clean()

    def test_bad_initial_signature_never_commits_script_config_certificate_or_state(self):
        original = self.old_auth()
        self.signature.write_text(self.fixtures['releases']['wrongsigner']['sig'])
        self.enroll(ok=False)
        self.assertEqual(self.auth.read_bytes(), original)
        for path in (self.installed, self.local_config, self.replay):
            self.assertFalse(path.exists())
        self.assertEqual(list((self.home / '.conf-sshd').glob('trust-*.asc')), [])
        self.assert_clean()

    def test_missing_replay_or_pinned_certificate_fails_closed(self):
        self.enroll()
        original = self.auth.read_bytes()
        saved = self.replay.read_bytes()
        self.replay.unlink()
        self.run_script('-o', ok=False)
        self.assertEqual(self.auth.read_bytes(), original)
        self.replay.write_bytes(saved)
        next((self.home / '.conf-sshd').glob('trust-*.asc')).unlink()
        self.run_script('-o', ok=False)
        self.assertEqual(self.auth.read_bytes(), original)

    def test_local_urls_fallback_order_and_signature_policy_never_downgrade(self):
        fallbacks = self.root / 'fallbacks'
        fallbacks.write_text(ORIGIN + '/mirror/ssh.keys\n')
        self.enroll(extra=('--fallback-urls-file', str(fallbacks)))
        self.calls.write_text('')
        self.run_script('-o', env={'TEST_KEY_STATUS':'503'})
        calls = self.calls.read_text()
        self.assertLess(calls.index(ORIGIN+'/ssh.keys'), calls.index(ORIGIN+'/mirror/ssh.keys'))
        self.assertIn('/mirror/ssh.keys.sig', calls)
        original = self.auth.read_bytes()
        self.run_script('-o', ok=False, env={'TEST_SIG_STATUS':'404', 'TEST_FALLBACK_SIG_STATUS':'404'})
        self.assertEqual(self.auth.read_bytes(), original)

    def test_persisted_config_is_strict_data_never_executed(self):
        self.enroll()
        original = self.auth.read_bytes()
        self.local_config.write_text(self.local_config.read_text() + 'touch ' + str(self.root/'PWNED') + '\n')
        self.run_script('-o', ok=False)
        self.assertFalse((self.root/'PWNED').exists())
        self.assertEqual(self.auth.read_bytes(), original)

    def test_floor_and_repository_defaults_require_consent(self):
        self.enroll(extra=('--min-sequence','6'), ok=False)
        self.assertFalse(self.replay.exists())
        defaults = SCRIPT.replace("DEFAULT_GPG_VERIFY='off'", "DEFAULT_GPG_VERIFY='on'").replace("DEFAULT_GPG_FINGERPRINT=''", f"DEFAULT_GPG_FINGERPRINT='{self.fixtures['primary']}'").replace("DEFAULT_LIST_ID=''", "DEFAULT_LIST_ID='fixture-list'")
        self.script.write_text(defaults)
        self.run_script('-o', ok=False)
        self.run_tty('-o', answer=self.fixtures['primary'])
        self.assertFalse(self.installed.exists())
        self.assertIn('policy required\n', self.local_config.read_text())
        self.script.write_text(SCRIPT)
        self.calls.write_text('')
        self.run_script('-o')
        self.assertIn('/ssh.keys.sig', self.calls.read_text())

    def test_disable_requires_terminal_and_preserves_reenable_rollback_floor(self):
        self.enroll()
        original_config = self.local_config.read_bytes()
        self.run_script('-o','--gpg-verification','off',ok=False)
        self.assertEqual(self.local_config.read_bytes(), original_config)
        self.run_tty('-o','--gpg-verification','off')
        self.assertIn('policy off\n', self.local_config.read_text())
        self.assertIn('sequence 5\n', self.replay.read_text())
        self.set_release('old')
        self.run_tty('-o','--gpg-verification','on',ok=False)
        self.assertIn('policy off\n', self.local_config.read_text())

    def test_explicit_reinstall_preserves_urls_pin_and_schedule(self):
        self.enroll(extra=('-c','7 1 * * 2'))
        before_config = self.local_config.read_bytes()
        before_cron = self.cron.read_bytes()
        old_script = self.installed.read_bytes()
        self.script.write_text(SCRIPT + '\n# local verified release\n')
        self.run_tty('--install')
        self.assertEqual(self.local_config.read_bytes(), before_config)
        self.assertEqual(self.cron.read_bytes(), before_cron)
        self.assertEqual(self.installed.read_bytes(), self.script.read_bytes())
        self.assertEqual(Path(str(self.installed)+'.conf-sshd.bak').read_bytes(), old_script)
        self.run_script('-u',ok=False)
        self.run_script('--install','--download-script',ok=False)
        self.assert_clean()

    def test_wrong_certificate_then_ordered_keyserver_fallback(self):
        self.enroll(extra=('--gpg-email','fixture@example.invalid'), ok=True)
        # A separate installation uses real cert parsing but all discovery mocked.
        self.run_script('--uninstall')
        self.local_config.unlink(); self.replay.unlink()
        for path in (self.home/'.conf-sshd').glob('trust-*.asc'): path.unlink()
        self.calls.write_text('')
        self.run_tty('--install','--gpg-verification','on','--gpg-fingerprint',self.fixtures['primary'],'--list-id','fixture-list','--gpg-email','fixture@example.invalid', env={'TEST_CERT_STATUS':'404','TEST_DISCOVERY_SUCCESS':'hkps://keyserver.ubuntu.com'})
        calls=self.calls.read_text()
        self.assertLess(calls.index('/public-key.gpg'),calls.index('--locate-external-keys'))
        self.assertLess(calls.index('--locate-external-keys'),calls.index('hkps://keys.openpgp.org'))
        self.assertLess(calls.index('hkps://keys.openpgp.org'),calls.index('hkps://keyserver.ubuntu.com'))
        self.assert_clean()

    def test_pending_journal_recovers_same_release_after_auth_replace_failure(self):
        self.enroll()
        self.set_release('next')
        real_mv=shutil.which('mv')
        self.mock('mv',f'''#!/bin/sh
last=
for arg do last=$arg; done
if [ "$last" = "$HOME/.ssh/authorized_keys" ]; then exit 74; fi
exec "{real_mv}" "$@"
''')
        # Force a changed authorized_keys body, while retaining its manual lines.
        self.old_auth(b'# existing manual\n')
        self.run_script('-o',ok=False)
        self.assertTrue((self.home/'.conf-sshd/pending.state').exists())
        self.assertTrue((self.home/'.conf-sshd/pending.bundle').exists())
        (self.bin/'mv').unlink()
        self.set_release('old')
        self.calls.write_text('')
        self.run_script('-o')
        self.assertIn('sequence 6\n',self.replay.read_text())
        self.assertNotIn('curl ',self.calls.read_text())
        self.assertFalse((self.home/'.conf-sshd/pending.state').exists())
        self.assertFalse((self.home/'.conf-sshd/pending.bundle').exists())
        self.assert_clean()

    def test_wrong_expired_revoked_and_multiple_certificate_rejected(self):
        for name in ('other','expired','revoked'):
            with self.subTest(name=name):
                self.cert.write_text(self.fixtures[name+'Key'])
                pin=self.fixtures[name+'Pin'] if name!='other' else self.fixtures['primary']
                self.enroll(pin=pin,ok=False)
                self.assertFalse(self.installed.exists())
                self.assertFalse(self.local_config.exists())
                self.assert_clean()
        self.cert.write_text(self.fixtures['publicKey']+self.fixtures['otherKey'])
        self.enroll(ok=False)
        self.assertFalse(self.installed.exists())


    def test_signed_pipe_install_requires_tty_then_installs_downloaded_release(self):
        defaults = SCRIPT.replace("DEFAULT_GPG_VERIFY='off'", "DEFAULT_GPG_VERIFY='on'").replace("DEFAULT_GPG_FINGERPRINT=''", f"DEFAULT_GPG_FINGERPRINT='{self.fixtures['primary']}'").replace("DEFAULT_LIST_ID=''", "DEFAULT_LIST_ID='fixture-list'")
        self.update.write_text(defaults)
        wrapper = self.root/'pipe-bootstrap.sh'
        prelude = shlex.quote(self.isolation_prelude())
        wrapper.write_text(f"{{ printf '%s' {prelude}; cat {shlex.quote(str(self.update))}; }} | {shlex.join(SHELL)} -s -- --install --download-script -c\n")
        self.run_script(script=wrapper,ok=False)
        self.assertFalse(self.installed.exists())
        self.assertNotIn('curl ',self.calls.read_text())
        self.run_tty(script=wrapper)
        self.assertEqual(self.installed.read_text(),defaults)
        self.assertIn('policy required\n',self.local_config.read_text())
        self.assertIn('/ssh.keys.sig',self.calls.read_text())
        self.assertIn('/script.sh',self.calls.read_text())
        self.assert_clean()

    def test_machine_status_rejects_weak_digest_text_signature_wrong_primary_and_errors(self):
        self.enroll()
        original=self.auth.read_bytes()
        real_gpg=shutil.which('gpg')
        self.mock('gpg',f'''#!/bin/sh
for arg do
    if [ "$arg" = --verify ]; then cat "$TEST_FAKE_STATUS"; exit 0; fi
done
exec "{real_gpg}" "$@"
''')
        path=self.root/'status-fixture'
        signer=self.fixtures['subkeys'][0]
        primary=self.fixtures['primary']
        good=f'[GNUPG:] VALIDSIG {signer} 2026-01-01 {int(time.time())-10} 0 4 0 1 8 00 {primary}\n'
        cases=[good.replace(' 8 00 ',' 11 00 '),good.replace(' 8 00 ',' 8 01 '),
               good.replace(' 0 4 0 ',' 1 4 0 '),good.replace(' 0 4 0 ',' 0 5 0 '),
               good.rstrip()+' extra\n',good.rsplit(' ',1)[0]+'\n',
               good+good,good+'[GNUPG:] KEYREVOKED\n',good+'[GNUPG:] BADARMOR\n',
               f'[GNUPG:] GOODSIG {signer[-16:]} fixture\n']
        for status in cases:
            with self.subTest(status=status):
                path.write_text(status)
                self.run_script('-o',ok=False,env={'TEST_FAKE_STATUS':str(path)})
                self.assertEqual(self.auth.read_bytes(),original)
                self.assert_clean()

    def test_rotation_preserves_sequence_and_explicit_floor_cannot_lower_it(self):
        self.enroll()
        original=self.local_config.read_bytes()
        self.cert.write_text(self.fixtures['otherKey'])
        self.payload.write_text(self.fixtures['releases']['next']['data'])
        self.signature.write_text(self.fixtures['otherSig'])
        self.enroll(pin=self.fixtures['otherPin'])
        self.assertNotEqual(self.local_config.read_bytes(),original)
        self.assertIn('sequence 6\n',self.replay.read_text())
        self.enroll(pin=self.fixtures['otherPin'],extra=('--min-sequence','5'),ok=False)
        self.assertIn('sequence 6\n',self.replay.read_text())
        self.enroll(pin=self.fixtures['otherPin'],extra=('--min-sequence','7'),ok=False)
        self.assertIn('sequence 6\n',self.replay.read_text())
        self.assert_clean()

    def test_missing_policy_does_not_reset_security_to_off(self):
        self.enroll()
        original=self.auth.read_bytes()
        self.local_config.unlink()
        self.run_script('-o',ok=False)
        self.assertEqual(self.auth.read_bytes(),original)

    def test_worker_certificate_failure_can_use_pinned_local_public_ring_without_mutation(self):
        ambient=self.root/'local-public-ring'
        ambient.mkdir(mode=0o700)
        subprocess.run(['gpg','--batch','--no-options','--no-autostart','--yes','--dearmor','--output',str(ambient/'pubring.gpg'),str(self.cert)],check=True,capture_output=True)
        before={x.name:x.read_bytes() for x in ambient.iterdir()}
        self.run_tty('--install','--gpg-verification','on','--gpg-fingerprint',self.fixtures['primary'],'--list-id','fixture-list',env={'GNUPGHOME':str(ambient),'TEST_CERT_STATUS':'404'})
        self.assertNotIn('/public-key.gpg',self.calls.read_text())
        self.assertEqual({x.name:x.read_bytes() for x in ambient.iterdir()},before)
        self.assert_clean()

    def test_corrupt_pending_package_blocks_reset_and_preserves_keys(self):
        self.enroll()
        original=self.auth.read_bytes()
        pending=self.home/'.conf-sshd/pending.bundle'
        pending.write_text('invalid\n')
        self.run_script('-o',ok=False)
        self.assertEqual(self.auth.read_bytes(),original)
        self.assertTrue(pending.exists())
        self.assertIn('sequence 5\n',self.replay.read_text())


    def test_expired_pending_is_not_applied_but_higher_fresh_release_can_progress(self):
        self.enroll()
        self.set_release('next')
        real_mv=shutil.which('mv')
        self.mock('mv',f'''#!/bin/sh
last=
for arg do last=$arg; done
if [ "$last" = "$HOME/.ssh/authorized_keys" ]; then exit 74; fi
exec "{real_mv}" "$@"
''')
        self.old_auth(b'# retained manual key\n')
        self.run_script('-o',ok=False)
        original=self.auth.read_bytes()
        (self.bin/'mv').unlink()
        now=int(time.time())+3700
        self.mock('date',f'#!/bin/sh\nprintf "%s\\n" "{now}"\n')
        self.set_release('old')
        self.run_script('-o',ok=False)
        self.assertEqual(self.auth.read_bytes(),original)
        self.assertTrue((self.home/'.conf-sshd/pending.state').exists())
        self.set_release('later')
        self.run_script('-o')
        self.assertIn('sequence 7\n',self.replay.read_text())
        self.assertFalse((self.home/'.conf-sshd/pending.state').exists())
        self.assertTrue(self.auth.read_bytes().startswith(original))
        self.assert_clean()

    def test_missing_security_state_does_not_block_stop_cron_or_uninstall(self):
        self.enroll(extra=('-c',))
        original=self.auth.read_bytes()
        self.replay.unlink()
        self.run_script('-c','false')
        self.assertNotIn(CB,self.cron.read_text())
        self.local_config.write_text('malformed but cleanup should work\n')
        self.run_script('--uninstall')
        self.assertFalse(self.installed.exists())
        self.assertEqual(self.auth.read_bytes(),original)

    def test_reinstall_reuses_dedicated_certificate_before_worker_and_keyservers(self):
        self.enroll()
        self.calls.write_text('')
        self.run_tty('--install',env={'TEST_CERT_STATUS':'404'})
        calls=self.calls.read_text()
        self.assertNotIn('/public-key.gpg',calls)
        self.assertNotIn('--recv-keys',calls)
        self.assertNotIn('--locate-external-keys',calls)
        self.assert_clean()

    def test_wkd_lookup_is_optional_bounded_and_stops_before_keyservers(self):
        self.run_tty('--install','--gpg-verification','on','--gpg-fingerprint',self.fixtures['primary'],'--list-id','fixture-list','--gpg-email','fixture@example.invalid',env={'TEST_CERT_STATUS':'404','TEST_DISCOVERY_SUCCESS':'wkd'})
        calls=self.calls.read_text()
        self.assertIn('--locate-external-keys -- fixture@example.invalid',calls)
        self.assertNotIn('--recv-keys',calls)
        self.assert_clean()

    def test_keyserver_override_replaces_builtins_and_remains_after_reinstall(self):
        server='hkps://keys.fixture.invalid'
        self.run_tty('--install','--gpg-verification','on','--gpg-fingerprint',self.fixtures['primary'],'--list-id','fixture-list','--keyserver',server,env={'TEST_CERT_STATUS':'404','TEST_DISCOVERY_SUCCESS':server})
        calls=self.calls.read_text()
        self.assertIn('--keyserver '+server,calls)
        self.assertNotIn('--keyserver hkps://keys.openpgp.org',calls)
        self.assertNotIn('--keyserver hkps://keyserver.ubuntu.com',calls)
        self.assertIn('keyserver '+server+'\n',self.local_config.read_text())
        self.assertNotIn('keys.openpgp.org',self.local_config.read_text())


    def test_failed_script_upgrade_never_activates_on_policy_over_legacy_script(self):
        self.installed.parent.mkdir(mode=0o700)
        self.installed.write_text('#!/bin/sh\n# legacy client without verification\n')
        old_script=self.installed.read_bytes()
        old_keys=self.old_auth()
        real_mv=shutil.which('mv')
        self.mock('mv',f'''#!/bin/sh
last=
for arg do last=$arg; done
if [ "$last" = "$HOME/.conf-sshd/conf-sshd.sh" ]; then exit 74; fi
exec "{real_mv}" "$@"
''')
        self.enroll(ok=False)
        self.assertEqual(self.installed.read_bytes(),old_script)
        self.assertEqual(self.auth.read_bytes(),old_keys)
        self.assertFalse(self.local_config.exists())
        self.assertFalse(self.replay.exists())
        self.assertEqual(list(self.installed.parent.glob('trust-*.asc')),[])

    def test_keys_only_enrollment_refuses_to_leave_legacy_scheduled_executable(self):
        self.installed.parent.mkdir(mode=0o700)
        self.installed.write_text('#!/bin/sh\n# old script\n')
        self.run_tty('-o','--gpg-verification','on','--gpg-fingerprint',self.fixtures['primary'],'--list-id','fixture-list',ok=False)
        self.assertFalse(self.local_config.exists())
        self.assertNotIn('curl ',self.calls.read_text())

    def test_install_cron_false_preserves_policy_and_never_uses_cleanup_bypass(self):
        self.enroll(extra=('-c',))
        original=self.local_config.read_bytes()
        self.run_tty('--install','-c','false')
        self.assertEqual(self.local_config.read_bytes(),original)
        self.assertNotIn(CB,self.cron.read_text())
        fresh=self.root/'other-home'
        fresh.mkdir(mode=0o700)
        self.run_script('--install','-c','false',env={'HOME':str(fresh)})
        self.assertIn('policy off\n',(fresh/'.conf-sshd/local.conf').read_text())

    def test_missing_dedicated_certificate_can_be_recovered_by_explicit_install(self):
        self.enroll()
        next((self.home/'.conf-sshd').glob('trust-*.asc')).unlink()
        self.run_tty('--install')
        self.assertTrue(next((self.home/'.conf-sshd').glob('trust-*.asc')).exists())
        self.assertIn('sequence 5\n',self.replay.read_text())


    def test_certificate_export_failure_continues_to_next_discovery_source(self):
        wrapper=self.bin/'gpg'
        text=wrapper.read_text()
        needle='home=; server=; action=\n'
        injected="""if [ \"${TEST_FAIL_FIRST_EXPORT:-0}\" = 1 ]; then
    for arg do
        if [ \"$arg\" = --export ] && [ ! -f \"$TEST_ROOT/export-failed-once\" ]; then
            : > \"$TEST_ROOT/export-failed-once\"
            exit 1
        fi
    done
fi
"""
        self.assertIn(needle,text)
        wrapper.write_text(text.replace(needle,injected+needle,1))
        self.run_tty('--install','--gpg-verification','on','--gpg-fingerprint',self.fixtures['primary'],'--list-id','fixture-list',env={'TEST_FAIL_FIRST_EXPORT':'1','TEST_DISCOVERY_SUCCESS':'hkps://keys.openpgp.org'})
        calls=self.calls.read_text()
        self.assertIn('/public-key.gpg',calls)
        self.assertIn('--keyserver hkps://keys.openpgp.org --recv-keys',calls)
        self.assertTrue((self.root/'export-failed-once').exists())
        self.assertTrue(self.installed.exists())
        self.assert_clean()


if __name__ == '__main__':
    suite=unittest.TestSuite()
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(ShellTests))
    suite.addTests(SignatureTests(name) for name in SignatureTests.__dict__ if name.startswith('test_'))
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(not result.wasSuccessful())
