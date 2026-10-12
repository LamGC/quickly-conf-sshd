#!/usr/bin/env python3
"""Installer integration tests. Every run uses a private HOME and mocked network/cron.
No SSH service, real account, real network, package manager, or production key is used.
"""
import hashlib
import base64
import struct
import signal
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'conf-sshd.sh').read_text()
SHELL = shlex.split(os.environ.get('CONF_SSHD_TEST_SHELL', '/bin/sh'))
ORIGIN = 'https://keys.example.test'
SCRIPT = SOURCE.replace('@@BASE_URL@@', ORIGIN).replace('@@DEFAULT_CRON@@', '*/15 * * * *')
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
case $url in */ssh.keys) cp "$TEST_RESPONSE" "$out" ;; */script.sh) cp "$TEST_UPDATE" "$out" ;; *) exit 99 ;; esac
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
        path.write_text(text)
        path.chmod(0o700)
        return path

    def run_script(self, *args, ok=True, env=None, script=None):
        completed = subprocess.run([*SHELL, str(script or self.script), *args],
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
        for option in ('--fail', '--proto =https', '--connect-timeout 10', '--max-time 30', '--retry 2'):
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
        self.assertNotIn('-u', text)
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
        first = subprocess.Popen([*SHELL, str(self.script), '-o'], env=env,
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
                self.run_script('-u', ok=False)
                self.assertEqual(self.installed.read_bytes(), original)
                self.assert_clean()
        self.run_script('-u', ok=False, env={'TEST_CURL_ERROR': '22'})
        self.update.write_text(SCRIPT + '\n# new release\n')
        self.run_script('-u')
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
        completed = subprocess.run([*SHELL, '-s', '--', '-c'], input=SCRIPT,
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
        self.run_script('-u')
        self.update.write_text(SCRIPT)
        self.run_script('-u', ok=False)

    def test_signal_removes_own_lock_and_temporary_files(self):
        first = subprocess.Popen([*SHELL, str(self.script), '-o'],
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


if __name__ == '__main__':
    unittest.main(verbosity=2)
