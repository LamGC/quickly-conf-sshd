#!/bin/sh
# conf-sshd-script-v2
# conf-sshd-client-security-v1
# Generated configuration. Never source or eval downloaded data.
BASE_URL='@@BASE_URL@@'
DEFAULT_CRON='@@DEFAULT_CRON@@'
DEFAULT_GPG_VERIFY='@@DEFAULT_GPG_VERIFY@@'
DEFAULT_GPG_FINGERPRINT='@@DEFAULT_GPG_FINGERPRINT@@'
DEFAULT_GPG_PIN_MODE='@@DEFAULT_GPG_PIN_MODE@@'
DEFAULT_LIST_ID='@@DEFAULT_LIST_ID@@'
DEFAULT_GPG_EMAIL='@@DEFAULT_GPG_EMAIL@@'

set -eu
umask 077
LC_ALL=C
PATH=${PATH:-/usr/bin:/bin}:/usr/local/sbin:/usr/sbin:/sbin
export LC_ALL PATH
BEGIN_KEYS='# --- BEGIN MANAGED BY CONF-SSHD SCRIPT ---'
END_KEYS='# --- END MANAGED BY CONF-SSHD SCRIPT ---'
BEGIN_CRON='# --- BEGIN CRON MANAGED BY CONF-SSHD SCRIPT ---'
END_CRON='# --- END CRON MANAGED BY CONF-SSHD SCRIPT ---'
mode=sync
cron_requested=no
cron_value=
dry_run=no
no_install=no
root_password=
apt_index_updated=no
cron_prepared=no
auth_prepared=no
temps=
lock_owned=no
lock_identity=
lock_reclaim_owned=no
lock_reclaim_identity=
lock_reclaim_parent=
retired_lock_parent=
retired_parent_identity=
retired_lock_identity=
retired_lock_pid=
retired_reclaim_identity=
created_state=no
created_ssh=no
gpg_home=
download_script=no
requested_verification=
config_prepared=no
validation_only=no
enforce_freshness=yes
replace_pending=no
public_key_file=
requested_fingerprint=
requested_pin_mode=
requested_list_id=
requested_min_sequence=
fallback_urls_file=
primary_url=
requested_email=
requested_keyservers=
trust_options=no

say() { printf '%s\n' "$*"; }
fail() { printf 'conf-sshd: %s\n' "$*" >&2; exit 1; }
usage() {
    cat <<'HELP'
Usage: sh conf-sshd.sh [options]
  (no options)                        Check/setup sshd for this user's privileges,
                                      then validate and sync managed keys
  -o, --only-update-keys               Keys only; never install packages or edit sshd
  -c, --cron ["five fields"|false]     Sync and schedule; bare -c keeps an existing
                                      schedule, otherwise the configured default.
                                      -c false only removes this script's schedule.
  --install                           Install/reinstall this trusted local file;
                                      retain local trust, URLs and existing schedule.
  --download-script                   With --install: HTTPS bootstrap/reinstall from
                                      Worker (explicit invocation only; never cron).
  --gpg-verification on|off            Explicitly enroll/change persisted verification;
                                      default from repository, existing config wins
  --gpg-required, --gpg-off            Aliases for --gpg-verification on/off
  --gpg-fingerprint FULL40HEX          Independently verified full fingerprint
  --gpg-pin-mode primary|subkey        Primary (default) trusts its valid signing
                                      subkeys; subkey permits only that exact subkey
  --public-key-file FILE               Explicit independently verified local certificate;
                                      supersedes cached/discovered certificate
  --list-id ID                         Required signed-list identity
  --min-sequence N                     Enrollment floor, default 1; never lowers state
  --gpg-email EMAIL                   Optional WKD identity during explicit install
  --keyserver HKPS_URL                 Override built-in ordered keyservers (repeat)
  --primary-url HTTPS_URL              Local first key endpoint; defaults to Worker
  --fallback-urls-file FILE            Ordered one-HTTPS-endpoint-per-line fallbacks
  -u, --update-self                    Refused: reinstall explicitly with --install
  --uninstall                         Remove own schedule/script; preserve keys/config
  -p, --allow-root-passwd yes|no       Root-only policy edit plus key sync; may use -c
                                      or --install; never reload sshd
  -n, --no-install-sshd                Skip SSH package bootstrap/server installation
  --dry-run                           Validate and show changes without applying them
  --status                            Show local installation and schedule status
  -h, --help                          Show this help

-u, --uninstall and --status are exclusive operations. -o cannot use -c or -p.
Trust/URL changes require explicit installation, or keys-only -o enrollment.
--install -c also schedules; --install always validates and syncs keys.
Running an installer from Worker explicitly trusts that bootstrap code. For higher
assurance, verify a downloaded file against an independently obtained SHA-256.
No installed script updates itself: cron runs only -o. Ordinary initial -c may
bootstrap from Worker over HTTPS; --install --download-script explicitly repeats
that bootstrap. HTTPS bootstrap trusts Worker and the transport at install time.
During enrollment, approve the full fingerprint and scope in your terminal.
No noninteractive trust-confirmation bypass is supported. Certificate discovery:
local public keyring, Worker /public-key.gpg, optional email WKD, then ordered
HKPS keyservers. Each candidate must match the complete primary/subkey pin.
Keyserver/WKD operators may learn the queried fingerprint/email and your IP.
A dedicated public-only certificate is saved locally; normal sync uses only it,
with no keyserver, WKD or certificate refresh. Reinstall reuses a valid local
certificate; --public-key-file explicitly supplies a verified replacement.
Built-in keyservers: hkps://keys.openpgp.org, hkps://keyserver.ubuntu.com.
A distributor can replay an old matching certificate that omits a revocation;
fingerprint pinning does not prove certificate freshness.
Strict mode needs GnuPG and a correct clock. A missing rollback-state file fails
closed. With --min-sequence omitted, initial enrollment cannot detect a previously
published, still-unexpired release being replayed; obtain a current floor out of band.
Expired/invalid responses retain last installed keys; expiry is not automatic revocation.
When verification is ON, two private audit slots retain successful original key
responses/signatures and signer/source/time metadata. Only the current pointer
marks a completed installation; an absent pointer with a pending journal means
recovery is needed. OFF key updates invalidate current audit without fetching a
signature. These files are locally editable by their owner, not tamper-proof.
Local state uses atomic renames and a pending journal, not a power-loss fsync guarantee.
Requires curl, ssh-keygen, awk, standard POSIX tools, mktemp, stat, and one of
sha256sum, shasum or openssl. Scheduling also requires crontab. Downloads require
HTTPS; existing keys survive any validation/download failure.
Normal root runs can install missing OpenSSH/cron using apt-get, dnf or yum.
Non-root users never install packages or change system SSH policy. -o is keys only.
Package hooks may start services or generate host keys. This script never directly
starts, restarts or reloads sshd. Keep recovery access ready.
The payload SHA-256 detects inconsistency; trust comes from HTTPS and its source.
HELP
}
select_mode() {
    [ "$mode" = sync ] || fail 'Conflicting or duplicate operation options.'
    mode=$1
}
while [ "$#" -gt 0 ]; do
    case $1 in
        -h|--help)
            if [ "$#" -ne 1 ] || [ "$mode" != sync ] || [ "$cron_requested" != no ]; then
                fail '--help must be used alone.'
            fi
            usage; exit 0 ;;
        -o|--only-update-keys) select_mode keys ;;
        -u|--update-self) select_mode update ;;
        --install) select_mode install ;;
        --download-script) [ "$download_script" = no ] || fail 'Duplicate --download-script.'; download_script=yes ;;
        --gpg-required|--gpg-off)
            [ -z "$requested_verification" ] || fail 'Duplicate GPG verification option.'
            if [ "$1" = --gpg-required ]; then requested_verification=on; else requested_verification=off; fi
            trust_options=yes ;;
        --gpg-verification|--public-key-file|--fingerprint|--gpg-fingerprint|--gpg-pin-mode|--gpg-email|--keyserver|--list-id|--min-sequence|--fallback-urls-file|--primary-url)
            option=$1
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                fail "$option requires a value."
            fi
            shift
            case $option in
                --gpg-verification) [ -z "$requested_verification" ] || fail "Duplicate $option."; requested_verification=$1 ;;
                --public-key-file) [ -z "$public_key_file" ] || fail "Duplicate $option."; public_key_file=$1 ;;
                --fingerprint|--gpg-fingerprint) [ -z "$requested_fingerprint" ] || fail "Duplicate $option."; requested_fingerprint=$1 ;;
                --gpg-pin-mode) [ -z "$requested_pin_mode" ] || fail "Duplicate $option."; requested_pin_mode=$1 ;;
                --list-id) [ -z "$requested_list_id" ] || fail "Duplicate $option."; requested_list_id=$1 ;;
                --min-sequence) [ -z "$requested_min_sequence" ] || fail "Duplicate $option."; requested_min_sequence=$1 ;;
                --fallback-urls-file) [ -z "$fallback_urls_file" ] || fail "Duplicate $option."; fallback_urls_file=$1 ;;
                --primary-url) [ -z "$primary_url" ] || fail "Duplicate $option."; primary_url=$1 ;;
                --gpg-email) [ -z "$requested_email" ] || fail "Duplicate $option."; requested_email=$1 ;;
                --keyserver) requested_keyservers="$requested_keyservers$1
" ;;
            esac
            trust_options=yes ;;
        --uninstall) select_mode uninstall ;;
        --status) select_mode status ;;
        -p|--allow-root-passwd)
            [ -z "$root_password" ] || fail 'Duplicate -p option.'
            [ "$#" -ge 2 ] || fail '-p requires yes or no.'
            shift; case $1 in yes|no) root_password=$1 ;; *) fail '-p requires yes or no.' ;; esac ;;
        -c|--cron)
            [ "$cron_requested" = no ] || fail 'Duplicate -c option.'
            cron_requested=yes
            if [ "$#" -gt 1 ]; then
                case $2 in -*) : ;; *) shift; cron_value=$1; [ -n "$cron_value" ] || fail 'Empty cron expression.' ;; esac
            fi ;;
        --dry-run) [ "$dry_run" = no ] || fail 'Duplicate --dry-run.'; dry_run=yes ;;
        -n|--no-install-sshd) [ "$no_install" = no ] || fail 'Duplicate -n.'; no_install=yes ;;
        *) fail "Unknown option or unexpected argument: $1" ;;
    esac
    shift
done
[ "$cron_requested" = no ] || [ "$mode" = sync ] || [ "$mode" = install ] || fail '-c cannot be combined with this operation.'
if [ -n "$root_password" ] && [ "$mode" != sync ] && [ "$mode" != install ]; then
    fail '-p cannot be combined with this operation.'
fi
[ "$trust_options" = no ] || [ "$mode" = install ] || [ "$mode" = keys ] || [ "$mode" = sync ] || fail 'Trust and URL settings require explicit installation or keys-only enrollment.'
case $requested_verification in ''|on|off) : ;; *) fail '--gpg-verification requires on or off.' ;; esac
[ "$download_script" = no ] || [ "$mode" = install ] || fail '--download-script requires --install.'
[ "$mode" != update ] || fail 'Remote self-update is disabled. Download and independently verify a local script, then run sh ./conf-sshd.sh --install. Explicit HTTPS bootstrap may use --install --download-script.'

need() { command -v "$1" >/dev/null 2>&1 || fail "Missing dependency: $1. Install it explicitly before continuing."; }
for dep in awk cat chmod cmp cp dd grep id mkdir mktemp mv od rm rmdir sed stat tail tr wc; do need "$dep"; done
uid=$(id -u)
if [ -n "$root_password" ] && [ "$uid" != 0 ]; then fail '-p requires root.'; fi
# Reject paths that could alter line-based cron records. Spaces and quotes are safe.
case ${HOME:-} in /*) : ;; *) fail 'HOME must be an absolute directory.' ;; esac
[ "$(printf '%s' "$HOME" | tr -d '\040-\176\200-\377'; printf .)" = . ] || fail 'HOME must not contain control characters.'
case $HOME in *\\*) fail 'HOME paths containing backslashes are not supported.' ;; esac
HOME=${HOME%/}
[ -n "$HOME" ] || fail 'HOME must not be the filesystem root.'
state=$HOME/.conf-sshd
ssh_dir=$HOME/.ssh
auth_file=$ssh_dir/authorized_keys
target_script=$state/conf-sshd.sh
local_config=$state/local.conf
replay_state=$state/replay.state
pending_bundle=$state/pending.bundle
pending_state=$state/pending.state
pending_source=$state/pending.source
audit_dir=$state/audit

# GNU/Linux and BSD/macOS stat. No filesystem changes precede ownership checks.
if stat -c '%u %a %h' "$HOME" >/dev/null 2>&1; then
    stat_info() { stat -c '%u %a %h' "$1"; }
    path_identity() { stat -c '%d:%i' "$1"; }
else
    stat_info() { stat -f '%u %Lp %l' "$1"; }
    path_identity() { stat -f '%d:%i' "$1"; }
fi
check_path() {
    checked=$1
    [ ! -L "$checked" ] || fail "Refusing symlink: $checked"
    if [ -e "$checked" ]; then
        if [ "$2" = dir ]; then [ -d "$checked" ] || fail "Not a directory: $checked"
        else [ -f "$checked" ] || fail "Not a regular file: $checked"; fi
        info=$(stat_info "$checked") || fail "Cannot inspect: $checked"
        # stat produces three numeric fields.
        # shellcheck disable=SC2086
        set -- $info
        [ "$1" = "$uid" ] || fail "Not owned by current user: $checked"
        case $2 in *[!0-7]*|'') fail "Cannot inspect permissions: $checked" ;; esac
        # Group/world writable paths allow races before an atomic replacement.
        [ "$((0$2 & 0022))" -eq 0 ] || fail "Group/world writable path: $checked"
        if [ -f "$checked" ]; then [ "$3" = 1 ] || fail "Refusing multiply linked file: $checked"; fi
    fi
}
check_path "$HOME" dir
[ -d "$HOME" ] || fail 'HOME does not exist.'
check_path "$state" dir
check_path "$ssh_dir" dir
check_path "$auth_file" file
check_path "$target_script" file
check_path "$local_config" file
check_path "$replay_state" file
check_path "$pending_bundle" file
check_path "$pending_state" file
check_path "$pending_source" file

validate_cron() {
    printf '%s\n' "$1" | awk '
    function number(s) { return s ~ /^[0-9]+$/ }
    function field(s,lo,hi, n,a,i,p,b,r,k,step) {
        if(s ~ /[^0-9*\/,\-]/ || s == "") return 0
        n=split(s,a,",")
        for(i=1;i<=n;i++) {
            p=split(a[i],b,"/"); if(p>2 || b[1]=="") return 0
            if(p==2 && (!number(b[2]) || b[2]+0<1 || b[2]+0>hi+1)) return 0
            if(b[1]=="*") continue
            r=split(b[1],k,"-"); if(r>2 || !number(k[1])) return 0
            if(k[1]+0<lo || k[1]+0>hi) return 0
            if(r==2 && (!number(k[2]) || k[2]+0<k[1]+0 || k[2]+0>hi)) return 0
        }
        return 1
    }
    NR!=1 || NF!=5 { exit 1 }
    { if(!field($1,0,59)||!field($2,0,23)||!field($3,1,31)||!field($4,1,12)||!field($5,0,7)) exit 1
      print $1 " " $2 " " $3 " " $4 " " $5 }
    END { if(NR!=1) exit 1 }'
}
if [ "$cron_requested" = yes ] && [ -n "$cron_value" ] && [ "$cron_value" != false ]; then
    cron_value=$(validate_cron "$cron_value") || fail 'Invalid cron expression; use five quoted numeric fields.'
fi

cleanup() {
    result=${1:-$?}
    trap - 0 HUP INT TERM
    old_ifs=$IFS; IFS='
'
    for path in $temps; do rm -f "$path"; done
    IFS=$old_ifs
    if [ -n "$gpg_home" ]; then
        if command -v gpgconf >/dev/null 2>&1; then gpgconf --homedir "$gpg_home" --kill all >/dev/null 2>&1 || :; fi
        rm -rf "$gpg_home"
    fi
    if [ -n "$retired_lock_parent" ]; then cleanup_retired_lock || :; fi
    # Never clean a replacement lock (or follow a replaced PID symlink).
    if [ "$lock_reclaim_owned" = yes ] && [ ! -L "$state/lock" ] &&
       [ "$(path_identity "$state/lock" 2>/dev/null)" = "$lock_reclaim_parent" ] &&
       [ ! -L "$state/lock/reclaim" ] && [ "$(path_identity "$state/lock/reclaim" 2>/dev/null)" = "$lock_reclaim_identity" ]; then
        rmdir "$state/lock/reclaim" 2>/dev/null || :
    fi
    if [ "$lock_owned" = yes ] && lock_matches "$$" 2>/dev/null; then
        rm -f "$state/lock/pid"
        rmdir "$state/lock" 2>/dev/null || :
    fi
    if [ "$dry_run" = yes ] || [ "$mode" = uninstall ]; then
        if [ "$created_ssh" = yes ]; then rmdir "$ssh_dir" 2>/dev/null || :; fi
        if [ "$created_state" = yes ] || [ "$mode" = uninstall ]; then rmdir "$state" 2>/dev/null || :; fi
    fi
    exit "$result"
}
new_temp() {
    TEMP=$(mktemp "$1/.conf-sshd.XXXXXX") || fail 'Cannot create secure temporary file.'
    temps="$temps
$TEMP"
    chmod 600 "$TEMP"
}
last_lf() { [ "$(tail -c 1 "$1" | od -An -tu1 | tr -d ' \n')" = 10 ]; }
quote_sh() { printf "'"; printf '%s' "$1" | sed "s/'/'\\\\''/g"; printf "'"; }
cron_command="/bin/sh $(quote_sh "$target_script") -o"
legacy_command="\"/bin/bash $target_script -o\" >> $state/run.log 2>&1"

if [ "$mode" = status ]; then
    [ "$dry_run" = no ] || fail '--status does not use --dry-run.'
    if [ -f "$target_script" ]; then say "Installed script: $target_script"; else say 'Script is not installed for scheduled use.'; fi
    if [ -f "$auth_file" ]; then say "Authorized keys: $auth_file (not modified)"; else say 'No authorized_keys file.'; fi
    if command -v crontab >/dev/null 2>&1; then
        if status_cron=$(crontab -l 2>&1); then
            say 'Current crontab (read-only):'; say "$status_cron"
        else
            case $status_cron in 'no crontab for '*) say 'No crontab is installed for this user.' ;;
                *) fail "Cannot read current crontab: $status_cron" ;; esac
        fi
    else say 'crontab is not installed.'; fi
    exit 0
fi

[ -d "$state" ] || { mkdir "$state"; created_state=yes; }
trap cleanup 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
read_lock_pid() {
    inspected_lock=${1:-$state/lock}
    check_path "$inspected_lock" dir
    [ -d "$inspected_lock" ] || return 1
    check_path "$inspected_lock/pid" file
    [ -f "$inspected_lock/pid" ] || return 1
    [ "$(wc -c < "$inspected_lock/pid" | tr -d ' ')" -le 11 ] || return 1
    # Accept legacy PID-only locks, including a missing final LF. Never signal
    # PID 0, a process group, or an unbounded/unvalidated integer.
    awk 'NR!=1 || $0 !~ /^[1-9][0-9]*$/ || length($0)>10 || $0+0>2147483647 {bad=1}
         END {exit(bad || NR!=1)}' "$inspected_lock/pid" || return 1
    cat "$inspected_lock/pid"
}
lock_matches() (
    matched_lock=${2:-$state/lock}
    matched_identity=${3:-$lock_identity}
    [ ! -L "$matched_lock" ] && [ -d "$matched_lock" ] || exit 1
    [ "$(path_identity "$matched_lock")" = "$matched_identity" ] || exit 1
    [ "$(read_lock_pid "$matched_lock")" = "$1" ]
)
cleanup_retired_lock() {
    [ ! -L "$retired_lock_parent" ] && [ -d "$retired_lock_parent" ] || return 1
    [ "$(path_identity "$retired_lock_parent")" = "$retired_parent_identity" ] || return 1
    if [ -e "$retired_lock_parent/lock" ] || [ -L "$retired_lock_parent/lock" ]; then
        lock_matches "$retired_lock_pid" "$retired_lock_parent/lock" "$retired_lock_identity" || return 1
        [ ! -L "$retired_lock_parent/lock/reclaim" ] || return 1
        [ "$(path_identity "$retired_lock_parent/lock/reclaim")" = "$retired_reclaim_identity" ] || return 1
        rm -f "$retired_lock_parent/lock/pid"
        rmdir "$retired_lock_parent/lock/reclaim" || return 1
        rmdir "$retired_lock_parent/lock" || return 1
    fi
    rmdir "$retired_lock_parent"
}
lock_process_state() {
    lock_process=unknown
    # A live reused PID is deliberately treated as occupied. Never kill an
    # owner or infer staleness from its executable name/start-time mismatch.
    if kill -0 "$lock_pid" 2>/dev/null; then lock_process=live; return; fi
    # kill -0 can fail for permissions. Require a successful all-process PID
    # snapshot before declaring absence. GNU/BSD accept -A; BusyBox ps does not
    # in every build, but its default selection includes all visible processes.
    # Do not fall back to plain "ps -o pid": GNU's default selection is narrower.
    if process_pids=$(ps -A -o pid 2>/dev/null); then :
    elif command -v busybox >/dev/null 2>&1 && process_pids=$(busybox ps -o pid 2>/dev/null); then :
    else return 0; fi
    # Verify the complete output, including our own PID; failed, empty or
    # malformed queries never turn an uncertain owner into a stale lock.
    lock_process=$(printf '%s\n' "$process_pids" | awk -v own="$$" -v owner="$lock_pid" '
        NR==1 {if(NF!=1 || $1!="PID") bad=1; next}
        NF!=1 || $1 !~ /^[1-9][0-9]*$/ || length($1)>10 || $1+0>2147483647 {bad=1; next}
        $1==own {self=1}
        $1==owner {live=1}
        END {if(bad || !self) print "unknown"; else if(live) print "live"; else print "dead"}
    ')
    # Recheck after the snapshot: a PID may have appeared while ps was running.
    if [ "$lock_process" = dead ] && kill -0 "$lock_pid" 2>/dev/null; then lock_process=live; fi
}
acquire_lock() {
    lock_recovered=no
    while :; do
        if mkdir "$state/lock" 2>/dev/null; then
            lock_identity=$(path_identity "$state/lock") || fail 'Cannot inspect the new lock.'
            (set -C; printf '%s\n' "$$" > "$state/lock/pid") || fail 'Cannot publish the new lock PID.'
            lock_owned=yes
            return
        fi
        check_path "$state/lock" dir
        [ -d "$state/lock" ] || fail 'Cannot create the run lock.'
        lock_identity=$(path_identity "$state/lock") || fail 'Cannot inspect the run lock.'
        lock_pid=$(read_lock_pid) || fail "Lock PID is missing or invalid; leave $state/lock in place and inspect it before removal."
        lock_matches "$lock_pid" || fail 'Run lock changed while being inspected; try again later.'
        lock_process_state
        case $lock_process in
            live) say "Another run holds $state/lock (PID $lock_pid); skipping."; exit 0 ;;
            unknown) fail 'Cannot prove that the lock owner exited; leaving the lock untouched.' ;;
        esac
        [ "$lock_recovered" = no ] || fail 'Run lock changed during recovery; try again later.'
        # Serialize stale recovery inside the exact old directory. A second
        # reaper must not rename/remove a newer lock acquired in the meantime.
        if ! mkdir "$state/lock/reclaim" 2>/dev/null; then
            check_path "$state/lock/reclaim" dir
            say 'Another run is recovering the stale lock; skipping.'
            exit 0
        fi
        lock_reclaim_identity=$(path_identity "$state/lock/reclaim")
        lock_reclaim_parent=$(path_identity "$state/lock")
        lock_reclaim_owned=yes
        lock_matches "$lock_pid" || fail 'Run lock changed during recovery; leaving it untouched.'
        lock_process_state
        [ "$lock_process" = dead ] || fail 'Lock owner may still be running; leaving the lock untouched.'
        for lock_entry in "$state/lock/"* "$state/lock/".[!.]* "$state/lock/"..?*; do
            [ -e "$lock_entry" ] || [ -L "$lock_entry" ] || continue
            case $lock_entry in "$state/lock/pid"|"$state/lock/reclaim") : ;;
                *) fail 'Unexpected lock contents; refusing automatic stale recovery.' ;; esac
        done
        # Retire the guarded inode atomically. Removing the in-directory guard
        # before rmdir would let a delayed second reaper wedge the empty lock.
        # A private empty destination prevents mv from merging into another run.
        # This coordinates cooperating runs; arbitrary path replacement by the
        # same UID is outside this lock's protection (as with the local state).
        retired_lock_parent=$(mktemp -d "$state/.conf-sshd.lock.XXXXXX") || fail 'Cannot prepare stale-lock recovery.'
        retired_parent_identity=$(path_identity "$retired_lock_parent")
        retired_lock_identity=$lock_identity
        retired_lock_pid=$lock_pid
        retired_reclaim_identity=$lock_reclaim_identity
        lock_matches "$lock_pid" || fail 'Run lock changed during recovery; leaving it untouched.'
        mv "$state/lock" "$retired_lock_parent/lock" || fail 'Cannot retire the stale lock.'
        lock_reclaim_owned=no
        cleanup_retired_lock || fail 'Retired lock changed; inspect it before removal.'
        retired_lock_parent=
        lock_recovered=yes
    done
}
acquire_lock
if [ "$dry_run" = no ]; then chmod 700 "$state"; fi

# Inputs are origin-only build constants; also reject unbuilt or corrupted scripts.
validate_build() {
    printf '%s\n' "$BASE_URL" | grep -Eq '^https://([A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:]+\])(:[0-9]{1,5})?$' || fail 'BASE_URL must be a configured HTTPS origin.'
    validate_cron "$DEFAULT_CRON" >/dev/null || fail 'Invalid or unbuilt default cron configuration.'
    case $DEFAULT_GPG_VERIFY in on|off) : ;; *) fail 'Invalid or unbuilt default GPG verification mode.' ;; esac
    case $DEFAULT_GPG_PIN_MODE in primary|subkey) : ;; *) fail 'Invalid or unbuilt default pin mode.' ;; esac
    if [ "$DEFAULT_GPG_VERIFY" = on ]; then
        printf '%s\n' "$DEFAULT_GPG_FINGERPRINT" | grep -Eq '^[0-9A-Fa-f]{40}$' || fail 'Invalid default GPG fingerprint.'
        printf '%s\n' "$DEFAULT_LIST_ID" | grep -Eq '^[A-Za-z0-9._-]{1,64}$' || fail 'Invalid default signed list ID.'
    fi
}
download() {
    need curl
    download_limit=${3:-1048576}
    download_timeout=${4:-30}
    download_failure=retrieval
    new_temp "$state"; download_headers=$TEMP
    # No redirects or curl retries. Caller owns the per-source attempt count.
    # Headers can only reject a failed candidate, never authorize its contents.
    curl_status=0
    http_status=$(curl --disable --fail --silent --show-error --proto '=https' --tlsv1.2 \
        --connect-timeout 10 --max-time "$download_timeout" --retry 0 \
        --max-filesize "$download_limit" --dump-header "$download_headers" \
        --output "$2" --write-out '%{http_code}' "$1") || curl_status=$?
    if [ "$http_status" = 503 ] && awk '
        {sub(/\r$/, "")}
        /^HTTP\// {count=0; validation=0; next}
        tolower($0) ~ /^x-conf-sshd-source-failure:/ {
            count++; value=$0; sub(/^[^:]*:[ \t]*/, "", value); sub(/[ \t]*$/, "", value)
            if(value=="validation") validation++
        }
        END {exit !(count==1 && validation==1)}' "$download_headers"; then
        download_failure=validation
    fi
    if [ "$curl_status" = 63 ]; then download_failure=validation; return 1; fi
    [ "$curl_status" = 0 ] && [ "$http_status" = 200 ] || return 1
    # An oversized response is deterministic invalid content, not transport.
    if [ "$(wc -c < "$2" | tr -d ' ')" -gt "$download_limit" ]; then download_failure=validation; return 1; fi
}
sha256() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 "$1" | awk '{print $NF}'
    else fail 'Install sha256sum, shasum, or openssl before syncing keys.'; fi
}
check_expected_file() {
    if [ "$2" = absent ]; then
        if [ -e "$1" ] || [ -L "$1" ]; then
            fail "File appeared concurrently; retry after reviewing: $1"
        fi
    else
        if [ ! -f "$1" ] || ! cmp -s "$1" "$2"; then
            fail "File changed concurrently; retry after reviewing: $1"
        fi
    fi
}
replace_file() {
    destination=$1; staged=$2; file_mode=$3
    check_path "$destination" file
    check_path "$destination.conf-sshd.bak" file
    if [ "$#" -ge 4 ]; then check_expected_file "$destination" "$4"; fi
    chmod "$file_mode" "$staged"
    if [ "$dry_run" = yes ]; then say "Would atomically replace $destination (mode $file_mode)."; return; fi
    if [ -f "$destination" ]; then
        new_temp "${destination%/*}"; backup_tmp=$TEMP
        cp "$destination" "$backup_tmp"; chmod 600 "$backup_tmp"
        if [ "$#" -ge 4 ]; then check_expected_file "$destination" "$4"; fi
        mv -f "$backup_tmp" "$destination.conf-sshd.bak"
    fi
    if [ "$#" -ge 4 ]; then check_expected_file "$destination" "$4"; fi
    mv -f "$staged" "$destination"
}
validate_script() {
    sh -n "$1" || fail 'Installer script has invalid shell syntax.'
    [ "$(grep -Fxc '# conf-sshd-script-v2' "$1" || :)" = 1 ] || fail 'Installer script is missing its unique version marker.'
    [ "$(grep -Fxc '# conf-sshd-client-security-v1' "$1" || :)" = 1 ] || fail 'Installer script lacks the fixed-client security version marker.'
    [ "$(grep -Fxc "BASE_URL='$BASE_URL'" "$1" || :)" = 1 ] || fail 'Installer script changed its configured origin.'
    [ "$(grep -Fxc "DEFAULT_CRON='$DEFAULT_CRON'" "$1" || :)" = 1 ] || fail 'Installer script has invalid default cron configuration.'
    if grep -Eq '@@[A-Z_]+@@' "$1"; then fail 'Installer script contains unexpanded build tokens.'; fi
}
prepare_script() {
    validate_build
    new_temp "$state"; script_tmp=$TEMP
    if [ "$download_script" = yes ] || [ "$mode" != install ]; then
        download "$BASE_URL/script.sh" "$script_tmp" || fail 'Installer download failed; existing script is unchanged.'
    else
        case $0 in /*|./*|../*) : ;; *) fail '--install requires an unambiguous local file path (sh ./conf-sshd.sh), or ordinary --download-script.' ;; esac
        case $0 in /dev/*|/proc/*|/sys/*) fail '--install cannot use stdin, a pipe, or a device file.' ;; esac
        check_path "$0" file
        [ -f "$0" ] || fail '--install requires a real local script file.'
        cp "$0" "$script_tmp"
    fi
    validate_script "$script_tmp"
}
install_script() {
    replace_file "$target_script" "$script_tmp" 700
    say 'Installed local script. Scheduled runs update keys only.'
}

sshd_present() { command -v sshd >/dev/null 2>&1; }
cron_present() { command -v crontab >/dev/null 2>&1; }
ssh_client_present() { command -v ssh-keygen >/dev/null 2>&1; }
select_package_manager() {
    if command -v apt-get >/dev/null 2>&1; then package_manager=apt-get
    elif command -v dnf >/dev/null 2>&1; then package_manager=dnf
    elif command -v yum >/dev/null 2>&1; then package_manager=yum
    else fail 'No supported package manager (apt-get, dnf or yum); install the missing dependency explicitly.'; fi
}
install_dependency() {
    [ "$uid" = 0 ] || fail 'Missing system dependency requires root; no privilege escalation is attempted.'
    select_package_manager
    case "$1:$package_manager" in
        client:apt-get) package=openssh-client ;;
        client:*) package=openssh-clients ;;
        server:*) package=openssh-server ;;
        cron:apt-get) package=cron ;;
        cron:*) package=crontabs ;;
        *) fail 'Unknown dependency request.' ;;
    esac
    if [ "$dry_run" = yes ]; then say "Would install $package using $package_manager."; return; fi
    say "Installing missing dependency $package using $package_manager. Package hooks may start services or generate host keys; this script never reloads sshd."
    case $package_manager in
        apt-get)
            if [ "$apt_index_updated" = no ]; then
                apt-get update || fail 'Package index update failed. No managed key/policy writes were attempted; package metadata may have changed.'
                apt_index_updated=yes
            fi
            apt-get install -y "$package" || fail 'Package installation failed or was partial. No managed key/policy writes were attempted; inspect package state before retrying.' ;;
        dnf) dnf install -y "$package" || fail 'Package installation failed or was partial; inspect dnf before retrying.' ;;
        yum) yum install -y "$package" || fail 'Package installation failed or was partial; inspect yum before retrying.' ;;
    esac
}
ensure_ssh_client() {
    if ssh_client_present; then return; fi
    if [ "$mode" = keys ] || [ "$no_install" = yes ] || [ "$uid" != 0 ]; then
        fail 'Missing ssh-keygen: install OpenSSH client tools explicitly (keys-only, -n and non-root runs never bootstrap packages).'
    fi
    install_dependency client
    if [ "$dry_run" = yes ]; then fail 'Cannot validate keys in a dry run without ssh-keygen; install the client dependency before retrying.'; fi
    ssh_client_present || fail 'OpenSSH client package completed but ssh-keygen is still unavailable; check PATH and package status.'
}
ensure_sshd() {
    if [ "$no_install" = yes ]; then say 'SSHD installation/check skipped (-n).'; return; fi
    if ! sshd_present; then
        [ "$uid" = 0 ] || fail 'SSHD is not installed and this is a non-root run. Ask an administrator to install it, or use -o for keys only.'
        install_dependency server
        if [ "$dry_run" = yes ]; then return; fi
        sshd_present || fail 'Server package completed but sshd is still unavailable; check PATH and package status.'
    fi
    if [ "$uid" = 0 ]; then
        sshd -T >/dev/null 2>&1 || fail 'SSHD exists but its configuration cannot be evaluated (invalid configuration or permissions). No reinstall was attempted; inspect sshd -T.'
    fi
}
ensure_cron() {
    if cron_present; then return; fi
    [ "$uid" = 0 ] || fail 'crontab is missing and this is a non-root run; ask an administrator to install cron.'
    install_dependency cron
    if [ "$dry_run" = yes ]; then return; fi
    cron_present || fail 'Cron package completed but crontab is still unavailable; check PATH and package status.'
}

# Rewrite only an exact paired managed block or the exact known legacy command.
# Unexpected cron errors and ambiguous/malformed managed entries fail closed.
prepare_cron() {
    need crontab
    case $HOME in *%*) fail 'Cron does not safely support a percent sign in HOME.' ;; esac
    new_temp "$state"; old_cron=$TEMP
    new_temp "$state"; cron_errors=$TEMP
    if crontab -l > "$old_cron" 2> "$cron_errors"; then :
    elif grep -Eq '^no crontab for [^[:cntrl:]]+$' "$cron_errors" && [ ! -s "$old_cron" ]; then :
    else fail 'Cannot read current crontab; refusing to replace it.'; fi
    new_temp "$state"; clean_cron=$TEMP
    new_temp "$state"; saved_schedule=$TEMP
    if last_lf "$old_cron"; then cron_lastlf=1; else cron_lastlf=0; fi
    CONF_CRON_COMMAND=$cron_command CONF_LEGACY_COMMAND=$legacy_command \
        awk -v begin="$BEGIN_CRON" -v end="$END_CRON" \
        -v saved="$saved_schedule" -v lastlf="$cron_lastlf" '
    BEGIN { command=ENVIRON["CONF_CRON_COMMAND"]; legacy=ENVIRON["CONF_LEGACY_COMMAND"] }
    function extract(line, rest,i,t,s) {
        rest=line; s=""
        for(i=1;i<=5;i++) {
            sub(/^[ \t]+/,"",rest)
            if(!match(rest,/^[^ \t]+/)) return ""
            t=substr(rest,1,RLENGTH); rest=substr(rest,RLENGTH+1)
            s=s (i==1 ? "" : " ") t
        }
        sub(/^[ \t]+/,"",rest)
        return rest==command || rest==legacy ? s : ""
    }
    { lines[NR]=$0
      if($0==begin) { if(block || began++) bad=1; block=1; drop[NR]=1; next }
      if($0==end) { if(!block || ended++) bad=1; block=0; drop[NR]=1; next }
      if($0 ~ /^[ \t]*#[ \t-]*(BEGIN|END)[ \t]+CRON MANAGED BY CONF-SSHD SCRIPT/) { bad=1; next }
      schedule=extract($0)
      if(block && schedule=="") bad=1
      if(schedule!="") { if(found++) bad=1; print schedule > saved; drop[NR]=1 }
    }
    END {
      if(block || began!=ended || (began && !found) || bad) exit 1
      for(i=1;i<=NR;i++) if(!drop[i]) { printf "%s",lines[i]; if(i<NR || lastlf) printf "\n" }
    }' "$old_cron" > "$clean_cron" || fail 'Malformed, ambiguous, or unfamiliar managed cron entry; left unchanged.'
    existing_schedule=$(cat "$saved_schedule")
    if [ -n "$existing_schedule" ]; then
        existing_schedule=$(validate_cron "$existing_schedule") || fail 'Existing managed cron expression is invalid.'
    fi
}
apply_cron() {
    if [ "$1" != false ]; then
        if [ -s "$clean_cron" ] && ! last_lf "$clean_cron"; then printf '\n' >> "$clean_cron"; fi
        printf '%s\n%s %s\n%s\n' "$BEGIN_CRON" "$1" "$cron_command" "$END_CRON" >> "$clean_cron"
    fi
    if cmp -s "$old_cron" "$clean_cron"; then say 'Managed cron is unchanged.'; return; fi
    if [ "$dry_run" = yes ]; then say "Would set managed cron: $1"; return; fi
    # Detect an independent crontab editor rather than overwrite concurrent edits.
    new_temp "$state"; check_cron=$TEMP
    if crontab -l > "$check_cron" 2> "$cron_errors"; then :
    elif grep -Eq '^no crontab for [^[:cntrl:]]+$' "$cron_errors" && [ ! -s "$check_cron" ]; then :
    else fail 'Cannot recheck current crontab.'; fi
    cmp -s "$old_cron" "$check_cron" || fail 'Crontab changed concurrently; retry after reviewing it.'
    crontab "$clean_cron" || fail 'Could not install crontab.'
    say "Managed cron set: $1"
}

validate_legacy_response() {
    last_lf "$response" || fail 'Key response must end with LF.'
    new_temp "$state"; invalid_bytes=$TEMP
    tr -d '\012\040-\176\200-\377' < "$response" > "$invalid_bytes"
    [ ! -s "$invalid_bytes" ] || fail 'Key response contains forbidden control bytes.'
    new_temp "$state"; metadata=$TEMP
    awk '
    NR==1 { if($0!="# conf-sshd-v1") exit 1 }
    NR==2 { if(substr($0,1,11)!="# revision " || length($0)!=51 || substr($0,12) ~ /[^0-9a-fA-F]/) exit 1; print substr($0,12) }
    NR==3 { if($0 !~ /^# key-count (0|[1-9][0-9]*)$/) exit 1; n=substr($0,13); if(n+0>10000) exit 1; print n }
    NR==4 { if($0!="# allow-empty yes" && $0!="# allow-empty no") exit 1; print substr($0,15) }
    NR==5 { if(substr($0,1,9)!="# sha256 " || length($0)!=73 || substr($0,10) ~ /[^0-9a-f]/) exit 1; print substr($0,10) }
    NR==6 { if($0!="# end-metadata") exit 1 }
    END { if(NR<6) exit 1 }' "$response" > "$metadata" || fail 'Invalid key-response metadata.'
    revision=$(sed -n '1p' "$metadata")
    key_count=$(sed -n '2p' "$metadata")
    allow_empty=$(sed -n '3p' "$metadata")
    expected_hash=$(sed -n '4p' "$metadata")
    new_temp "$state"; payload=$TEMP
    tail -n +7 "$response" > "$payload"
    [ "$(sha256 "$payload")" = "$expected_hash" ] || fail 'Payload SHA-256 mismatch.'
    [ "$(wc -l < "$payload" | tr -d ' ')" = "$key_count" ] || fail 'Payload key count mismatch.'
    if [ "$key_count" = 0 ]; then [ "$allow_empty" = yes ] || fail 'Empty key set was not explicitly allowed.'; fi
    validate_payload
}
validate_payload() {
    awk -v strict="$policy" '
    {
      if(strict=="required" && NF!=2) exit 1
      if($0 ~ /[ \t]$/ || $0 !~ /^[^ ]+ [^ ]+( [^ ].*)?$/ || NF<2) exit 1
      if($1!="ssh-ed25519" && $1!="ssh-rsa" && $1!="ecdsa-sha2-nistp256" && $1!="ecdsa-sha2-nistp384" && $1!="ecdsa-sha2-nistp521" && $1!="sk-ssh-ed25519@openssh.com" && $1!="sk-ecdsa-sha2-nistp256@openssh.com") exit 1
      if($2 !~ /^[A-Za-z0-9+\/]+={0,2}$/) {
        # POSIX awk implementations without interval-expression support.
        blob=$2; sub(/==?$/,"",blob); if(blob=="" || blob ~ /[^A-Za-z0-9+\/]/) exit 1
      }
      if(length($2)%4!=0 || seen[$1 " " $2]++) exit 1
      if($2 ~ /==$/ && substr($2,length($2)-2,1) !~ /^[AQgw]$/) exit 1
      if($2 ~ /[^=]=$/ && substr($2,length($2)-1,1) !~ /^[AEIMQUYcgkosw048]$/) exit 1
    }' "$payload" || fail 'Invalid, duplicate, unsupported, or noncanonical public key line.'
    new_temp "$state"; one_key=$TEMP
    new_temp "$state"; key_info=$TEMP
    while IFS= read -r key_line; do
        printf '%s\n' "$key_line" > "$one_key"
        ssh-keygen -l -f "$one_key" > "$key_info" 2>/dev/null || fail 'ssh-keygen rejected a public key.'
        case $key_line in ssh-rsa\ *)
            bits=$(awk 'NR==1 {print $1}' "$key_info")
            case $bits in ''|*[!0-9]*) fail 'Cannot determine RSA key size.' ;; esac
            [ "$bits" -ge 2048 ] || fail 'RSA keys must be at least 2048 bits.' ;;
        esac
    done < "$payload"
}
prepare_authorized_keys() {
    [ -d "$ssh_dir" ] || { mkdir "$ssh_dir"; created_ssh=yes; }
    # Existing secure directory permissions need not be changed in dry-run mode.
    if [ "$dry_run" = no ]; then chmod 700 "$ssh_dir"; fi
    check_path "$auth_file" file
    new_temp "$ssh_dir"; new_auth=$TEMP
    auth_snapshot=absent
    if [ -f "$auth_file" ]; then
        new_temp "$state"; auth_snapshot=$TEMP
        cp "$auth_file" "$auth_snapshot"

        new_temp "$state"; bounds=$TEMP
        bytes=$(wc -c < "$auth_snapshot" | tr -d ' ')
        awk -v begin="$BEGIN_KEYS" -v end="$END_KEYS" -v size="$bytes" '
        { start=offset+0; offset+=length($0)+1
          if($0==begin) { if(inblock || began++) bad=1; inblock=1; first=start }
          else if($0==end) { if(!inblock || ended++) bad=1; inblock=0; last=offset }
          else if($0 ~ /^[ \t]*#[ \t-]*(BEGIN|END)[ \t]+MANAGED BY CONF-SSHD SCRIPT/) bad=1
        }
        END { if(inblock || began!=ended || bad) exit 1
              if(began) print first " " (last>size ? size : last); else print "absent" }
        ' "$auth_snapshot" > "$bounds" || fail 'Malformed or duplicate authorized_keys managed markers; left unchanged.'
        positions=$(cat "$bounds")
        if [ "$positions" = absent ]; then
            cat "$auth_snapshot" > "$new_auth"
            if [ -s "$new_auth" ] && ! last_lf "$new_auth"; then printf '\n' >> "$new_auth"; fi
            {
                printf '%s\n' "$BEGIN_KEYS"
                cat "$payload"
                printf '%s\n' "$END_KEYS"
            } >> "$new_auth"
        else
            # Validated awk output: two decimal offsets.
            # shellcheck disable=SC2086
            set -- $positions
            dd if="$auth_snapshot" bs=1 count="$1" 2>/dev/null > "$new_auth"
            {
                printf '%s\n' "$BEGIN_KEYS"
                cat "$payload"
                printf '%s\n' "$END_KEYS"
                dd if="$auth_snapshot" bs=1 skip="$2" 2>/dev/null
            } >> "$new_auth"
        fi
    else
        {
            printf '%s\n' "$BEGIN_KEYS"
            cat "$payload"
            printf '%s\n' "$END_KEYS"
        } > "$new_auth"
    fi
    check_path "$auth_file" file
    check_expected_file "$auth_file" "$auth_snapshot"
    auth_prepared=yes
}
commit_authorized_keys() {
    check_path "$auth_file" file
    check_expected_file "$auth_file" "$auth_snapshot"
    if [ "$auth_snapshot" != absent ] && cmp -s "$auth_snapshot" "$new_auth"; then
        if [ "$dry_run" = no ]; then chmod 600 "$auth_file"; fi
        say "Keys unchanged ($key_count keys, revision $revision)."
    else
        replace_file "$auth_file" "$new_auth" 600 "$auth_snapshot"
        say "Validated $key_count keys at revision $revision."
    fi
}

apply_payload() {
    if [ "$auth_prepared" = no ]; then prepare_authorized_keys; fi
    if [ "$policy" = off ]; then invalidate_audit_current; fi
    commit_authorized_keys
}

# Support the standard global drop-in directory only. Never evaluate arbitrary
# Include globs from configuration or assume a handful of Match contexts suffice.
inspect_config_directives() {
    awk -v allow="$2" -v standard="$include_dir/*.conf" '
    function directive(line, name) {
      sub(/^[[:space:]]*/,"",line)
      if(substr(line,1,1)=="#") return ""
      name=line
      if(substr(name,1,1)=="\"") {name=substr(name,2);sub(/\".*$/,"",name)}
      else sub(/[[:space:]=].*$/,"",name)
      return tolower(name)
    }
    {
      name=directive($0)
      if(name=="match") exit 1
      if(name=="include") {
        if(allow!="yes") exit 1
        line=$0; sub(/^[[:space:]]*/,"",line)
        token=line; sub(/[[:space:]].*$/,"",token)
        if(tolower(token)!="include") exit 1
        sub(/^[^[:space:]]+[[:space:]]+/,"",line)
        sub(/[[:space:]]+#.*$/,"",line); sub(/[[:space:]]*$/,"",line)
        if(line!=standard && line!="sshd_config.d/*.conf") exit 1
        includes=1
      }
    }
    END {if(includes) print "yes"}
    ' "$1"
}
list_standard_includes() {
    : > "$1"
    check_path "$include_dir" dir
    if [ -d "$include_dir" ]; then
        for include_file in "$include_dir"/*.conf; do
            if [ ! -e "$include_file" ] && [ ! -L "$include_file" ]; then continue; fi
            check_path "$include_file" file
            [ "$(printf '%s' "$include_file" | tr -d '\040-\176\200-\377'; printf .)" = . ] || fail 'Unsupported control character in SSH drop-in filename.'
            printf '%s\n' "$include_file" >> "$1"
        done
    fi
}
snapshot_standard_includes() {
    new_temp "$state"; include_inventory=$TEMP
    list_standard_includes "$include_inventory"
    if [ -d "$include_dir" ]; then include_directory_state=present; else include_directory_state=absent; fi
    new_temp "$state"; include_snapshots=$TEMP
    while IFS= read -r include_file; do
        new_temp "$state"; include_snapshot=$TEMP
        cp "$include_file" "$include_snapshot"
        inspect_config_directives "$include_snapshot" no >/dev/null || fail 'SSH drop-ins contain Match or nested Include; review root-login policy manually.'
        printf '%s\t%s\n' "$include_file" "$include_snapshot" >> "$include_snapshots"
    done < "$include_inventory"
}
check_standard_includes() {
    new_temp "$state"; checked_inventory=$TEMP
    list_standard_includes "$checked_inventory"
    if [ "$include_directory_state" = absent ] && [ -d "$include_dir" ]; then fail 'SSH drop-in directory appeared concurrently; retry after reviewing it.'; fi
    if [ "$include_directory_state" = present ] && [ ! -d "$include_dir" ]; then fail 'SSH drop-in directory disappeared concurrently; retry after reviewing it.'; fi
    cmp -s "$include_inventory" "$checked_inventory" || fail 'SSH drop-in filename inventory changed concurrently; retry after reviewing it.'
    tab=$(printf '\t')
    while IFS="$tab" read -r include_file include_snapshot; do
        check_path "$include_file" file
        check_expected_file "$include_file" "$include_snapshot"
    done < "$include_snapshots"
}

prepare_sshd_config() {
    [ "$uid" = 0 ] || fail '-p requires root.'
    need sshd
    config=/etc/ssh/sshd_config
    check_path /etc/ssh dir
    check_path "$config" file
    [ -f "$config" ] || fail 'sshd_config does not exist; install/configure sshd yourself first.'
    new_temp /etc/ssh; sshd_snapshot=$TEMP
    cp "$config" "$sshd_snapshot"
    include_dir=/etc/ssh/sshd_config.d
    allowed_includes=$(inspect_config_directives "$sshd_snapshot" yes) || fail 'sshd_config uses Match or an unsupported Include. Only the standard sshd_config.d/*.conf global include is supported; review other layouts manually.'
    if [ "$allowed_includes" = yes ]; then snapshot_standard_includes; fi
    sshd -t -f "$config" || fail 'Existing sshd_config is invalid.'
    new_temp /etc/ssh; sshd_staged=$TEMP
    if [ "$root_password" = yes ]; then setting=yes; else setting=prohibit-password; fi
    awk -v value="$setting" '
    BEGIN { print "PermitRootLogin " value }
    { name=$0; sub(/^[[:space:]]*/,"",name)
      if(substr(name,1,1)=="\"") { name=substr(name,2); sub(/\".*$/,"",name) }
      else sub(/[[:space:]=].*$/,"",name)
      if(tolower(name)!="permitrootlogin") print
    }
    ' "$sshd_snapshot" > "$sshd_staged"
    sshd -t -f "$sshd_staged" || fail 'Staged sshd_config failed validation.'
    new_temp "$state"; effective=$TEMP
    sshd -T -f "$sshd_staged" > "$effective" || fail 'Cannot evaluate staged sshd_config.'
    actual=$(awk '$1=="permitrootlogin" {print $2}' "$effective")
    case "$setting:$actual" in yes:yes|prohibit-password:prohibit-password|prohibit-password:without-password) : ;; *) fail 'Effective root-login policy does not match the requested setting.' ;; esac
    if [ "$allowed_includes" = yes ]; then check_standard_includes; fi
}
commit_sshd_config() {
    if [ "$allowed_includes" = yes ]; then check_standard_includes; fi
    replace_file "$config" "$sshd_staged" 600 "$sshd_snapshot"
    say 'Root-login policy validated. No service reload was performed; test recovery access before applying it.'
    [ "$root_password" != yes ] || say 'PermitRootLogin yes does not enable PasswordAuthentication if it is disabled elsewhere.'
}

# All persistent policy/state is a data format with a strict parser, never shell code.
validate_url() {
    [ "${#1}" -le 2048 ] || return 1
    printf '%s\n' "$1" | grep -Eq '^https://([A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:]+\])(:[0-9]{1,5})?(/[!-~]*)?$' || return 1
    case $1 in *'?'*|*'#'*|*\\*) return 1 ;; esac
}
strict_text() {
    last_lf "$1" || fail 'Local data must end with LF.'
    new_temp "$state"; invalid_local=$TEMP
    tr -d '\012\040-\176' < "$1" > "$invalid_local"
    [ ! -s "$invalid_local" ] || fail 'Local data contains non-ASCII or control bytes.'
}
validate_urls() {
    [ -s "$1" ] || fail 'At least one source URL is required.'
    [ "$(wc -l < "$1" | tr -d ' ')" -le 6 ] || fail 'At most six source URLs (primary plus five fallbacks) are allowed.'
    while IFS= read -r source_url; do
        validate_url "$source_url" || fail 'Invalid HTTPS source URL; query strings, fragments and credentials are unsupported.'
    done < "$1"
    awk 'seen[$0]++ {exit 1}' "$1" || fail 'Duplicate source URL.'
}
load_local_config() {
    policy=off
    list_id=-
    pinned_fingerprint=-
    pin_mode=primary
    gpg_email=-
    keyservers="hkps://keys.openpgp.org
hkps://keyserver.ubuntu.com"
    config_snapshot=absent
    new_temp "$state"; urls=$TEMP
    printf '%s/ssh.keys\n' "$BASE_URL" > "$urls"
    if [ -f "$local_config" ]; then
        new_temp "$state"; config_snapshot=$TEMP
        cp "$local_config" "$config_snapshot"
        [ "$(wc -c < "$config_snapshot" | tr -d ' ')" -le 40000 ] || fail 'Local configuration is too large.'
        strict_text "$config_snapshot"
        awk '
        NR==1 { if($0!="conf-sshd-local-v1") exit 1 }
        NR==2 { if($0!="policy off" && $0!="policy required") exit 1; p=$2 }
        NR==3 { if($0!="list-id " $2 || $2 ~ /[^A-Za-z0-9._-]/ || length($2)<1 || length($2)>64) exit 1; l=$2 }
        NR==4 { if($0!="fingerprint " $2) exit 1; f=$2
          if(p=="required" && (length(f)!=40 || f ~ /[^0-9A-F]/ || l=="-")) exit 1
          if(p=="off" && !((f=="-" && l=="-") || (length(f)==40 && f !~ /[^0-9A-F]/ && l!="-"))) exit 1 }
        NR==5 {if($0!="pin-mode primary" && $0!="pin-mode subkey") exit 1; if(f=="-" && $2!="primary") exit 1}
        NR==6 { if($0!="email " $2 || $2=="") exit 1 }
        NR>6 { if(substr($0,1,4)=="url ") {u++; if(k) exit 1} else if(substr($0,1,10)=="keyserver ") k++; else exit 1 }
        END { if(NR<8 || NR>16 || u<1 || u>6 || k<1 || k>4) exit 1 }
        ' "$config_snapshot" || fail 'Malformed local configuration; refusing to guess or downgrade.'
        policy=$(sed -n '2s/^policy //p' "$config_snapshot")
        list_id=$(sed -n '3s/^list-id //p' "$config_snapshot")
        pinned_fingerprint=$(sed -n '4s/^fingerprint //p' "$config_snapshot")
        pin_mode=$(sed -n '5s/^pin-mode //p' "$config_snapshot")
        gpg_email=$(sed -n '6s/^email //p' "$config_snapshot")
        keyservers=$(sed -n '7,$s/^keyserver //p' "$config_snapshot")
        sed -n '7,$s/^url //p' "$config_snapshot" > "$urls"
    elif [ -e "$replay_state" ] || [ -e "$pending_state" ] || [ -e "$pending_bundle" ]; then
        fail 'Local policy is missing while security state exists; refusing an implicit downgrade.'
    fi
    validate_urls "$urls"
    validate_discovery_settings
    if [ "$policy" = required ] && [ "$mode" != uninstall ] && [ "$cron_value" != false ] && [ "$requested_verification" != off ]; then
        trust_key=$state/trust-$pinned_fingerprint-$pin_mode.asc
        check_path "$trust_key" file
        [ -f "$trust_key" ] || [ "$mode" = install ] || [ "$trust_options" = yes ] || fail 'Dedicated pinned certificate is missing; reinstall explicitly to recover it.'
        [ -f "$replay_state" ] || fail 'Rollback state is missing after enrollment; refusing silent bootstrap.'
    fi
}
new_gpg_home() {
    need gpg
    if [ -z "$gpg_home" ]; then
        gpg_home=$(mktemp -d "$state/.conf-sshd-gpg.XXXXXX") || fail 'Cannot create isolated GnuPG directory.'
        chmod 700 "$gpg_home"
    fi
}
gpg_local() {
    gpg --batch --no-options --homedir "$gpg_home" --no-tty --no-autostart \
        --no-auto-key-retrieve --auto-key-locate clear --no-default-keyring \
        --keyring "$gpg_home/pinned.gpg" "$@"
}
import_pinned_key() {
    new_gpg_home
    [ "$(wc -c < "$1" | tr -d ' ')" -le 1048576 ] || fail 'Public key file exceeds 1 MiB.'
    new_temp "$state"; key_description=$TEMP
    gpg_local --with-colons --show-keys "$1" > "$key_description" 2>/dev/null || fail 'Cannot inspect local OpenPGP public key.'
    current_time=$(date +%s)
    temps="$temps
$key_description.primary"
    awk -F: -v pin="$pinned_fingerprint" -v mode="$pin_mode" -v now="$current_time" '
    $1=="sec" || $1=="ssb" { bad=1 }
    $1=="pub" || $1=="sub" {
      kind=$1; valid=($2 !~ /[redi]/ && ($7=="" || $7+0>now)); signing=($12 ~ /[sS]/)
      if(kind=="pub" && (++p!=1 || !valid)) bad=1
      want=1; next
    }
    $1=="fpr" && want {
      if(kind=="pub") primary=$10
      if($10==pin && ((mode=="primary" && kind=="pub") || (mode=="subkey" && kind=="sub"))) {matched++; if(!valid || !signing) bad=1}
      want=0
    }
    END {if(bad || p!=1 || matched!=1 || length(primary)!=40 || primary ~ /[^0-9A-F]/) exit 1; print primary}
    ' "$key_description" > "$key_description.primary" || fail 'Certificate must contain exactly one current primary and the expected current primary/subkey fingerprint, with no secret keys.'
    certificate_primary=$(cat "$key_description.primary")
    gpg_local --yes --dearmor --output "$gpg_home/pinned.gpg" "$1" >/dev/null 2>&1 || fail 'Cannot prepare isolated public-only certificate keyring.'
}
validate_discovery_settings() {
    if [ "$gpg_email" != - ]; then
        if [ "${#gpg_email}" -le 254 ] && printf '%s\n' "$gpg_email" | grep -Eq '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$'; then :
        else fail 'Invalid WKD email address.'; fi
    fi
    new_temp "$state"; server_list=$TEMP
    printf '%s\n' "$keyservers" > "$server_list"
    [ "$(wc -l < "$server_list" | tr -d ' ')" -le 4 ] || fail 'At most four keyservers are permitted.'
    while IFS= read -r server; do
        printf '%s\n' "$server" | grep -Eq '^hkps://[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?$' || fail 'Keyservers must be explicit HKPS origins.'
    done < "$server_list"
}
reset_gpg_home() {
    if [ -n "$gpg_home" ]; then
        # Kill only services belonging to our private transient home, if any.
        if command -v gpgconf >/dev/null 2>&1; then gpgconf --homedir "$gpg_home" --kill all >/dev/null 2>&1 || :; fi
        rm -rf "$gpg_home"
        gpg_home=
    fi
    new_gpg_home
}
accept_certificate_candidate() {
    # A separate clean keyring per discovery candidate prevents unrelated keys
    # or a rejected certificate from contaminating the final verifier.
    reset_gpg_home
    new_temp "$state"; candidate_export=$TEMP
    if ( lock_owned=no; created_state=no; created_ssh=no; temps=; candidate_result=0
         trap 'candidate_result=$?; gpg_home=; cleanup "$candidate_result"' 0
         import_pinned_key "$1"
         gpg_local --armor --export "$certificate_primary" > "$candidate_export" || fail 'Candidate certificate cannot be exported by this GnuPG version.'
         if [ -s "$candidate_export" ] && [ "$(wc -c < "$candidate_export" | tr -d ' ')" -le 1048576 ]; then :
         else fail 'Candidate public certificate export is empty or oversized.'; fi ); then
        import_pinned_key "$candidate_export"
        staged_trust=$candidate_export
        trust_key=$state/trust-$pinned_fingerprint-$pin_mode.asc
        check_path "$trust_key" file
        return 0
    fi
    return 1
}
lookup_bounded() {
    now=$(date +%s)
    remaining=$((discovery_deadline - now))
    [ "$remaining" -gt 0 ] || return 1
    if [ "$remaining" -gt 15 ]; then remaining=15; fi
    if command -v timeout >/dev/null 2>&1; then timeout -k 2 "$remaining" "$@"
    elif command -v gtimeout >/dev/null 2>&1; then gtimeout -k 2 "$remaining" "$@"
    else say 'Skipping WKD/keyserver lookup: a timeout or gtimeout utility is required.' >&2; return 1; fi
}
discover_certificate() {
    discovery_deadline=$(($(date +%s) + 120))
    new_temp "$state"; candidate=$TEMP
    if [ -n "$public_key_file" ]; then
        check_path "$public_key_file" file
        [ -f "$public_key_file" ] || fail 'Local public key file does not exist.'
        accept_certificate_candidate "$public_key_file" || fail 'Explicit certificate failed validation; refusing to fall back to a possibly stale certificate.'
        return
    fi
    existing_trust=$state/trust-$pinned_fingerprint-$pin_mode.asc
    check_path "$existing_trust" file
    if [ -f "$existing_trust" ]; then
        accept_certificate_candidate "$existing_trust" || fail 'Existing dedicated certificate is expired, revoked or invalid; supply an independently verified replacement explicitly.'
        return
    fi
    ambient_home=${GNUPGHOME:-$HOME/.gnupg}
    if [ -d "$ambient_home" ]; then
        # Read/export only: no import, trust edits or remote lookup in this home.
        if gpg --batch --no-options --homedir "$ambient_home" --no-tty --no-autostart \
            --no-auto-key-retrieve --auto-key-locate clear --no-auto-check-trustdb \
            --lock-never --export "$pinned_fingerprint" > "$candidate" 2>/dev/null && [ -s "$candidate" ]; then
            if accept_certificate_candidate "$candidate"; then return; fi
        fi
    fi
    if download "$BASE_URL/public-key.gpg" "$candidate" 1048576; then
        if accept_certificate_candidate "$candidate"; then return; fi
    fi
    if [ "$gpg_email" != - ]; then
        reset_gpg_home
        if lookup_bounded gpg --batch --no-options --homedir "$gpg_home" --no-tty \
            --no-auto-key-retrieve --auto-key-locate clear,wkd --locate-external-keys -- "$gpg_email" >/dev/null 2>&1; then
            gpg --batch --no-options --homedir "$gpg_home" --no-tty --no-autostart --no-auto-key-retrieve --auto-key-locate clear --armor --export > "$candidate" 2>/dev/null || :
            if accept_certificate_candidate "$candidate"; then return; fi
        fi
    fi
    while IFS= read -r server; do
        reset_gpg_home
        if lookup_bounded gpg --batch --no-options --homedir "$gpg_home" --no-tty \
            --no-auto-key-retrieve --auto-key-locate clear --keyserver "$server" \
            --recv-keys "$pinned_fingerprint" >/dev/null 2>&1; then
            gpg --batch --no-options --homedir "$gpg_home" --no-tty --no-autostart --no-auto-key-retrieve --auto-key-locate clear --armor --export > "$candidate" 2>/dev/null || :
            if accept_certificate_candidate "$candidate"; then return; fi
        fi
    done < "$server_list"
    fail 'No local, Worker, WKD or configured keyserver certificate matched the complete trusted pin; nothing installed.'
}
read_replay_state() {
    strict_text "$1"
    [ "$(wc -c < "$1" | tr -d ' ')" -le 256 ] || fail 'Rollback state is oversized.'
    awk -v list="$list_id" '
    NR==1 { if($0!="conf-sshd-state-v1") exit 1 }
    NR==2 { if($0!="list-id " list) exit 1 }
    NR==3 { if($0!="sequence " $2 || $2 !~ /^(0|[1-9][0-9]*)$/ || length($2)>10 || $2+0>2147483647) exit 1 }
    NR==4 { if($0!="sha256 " $2 || ($2!="-" && (length($2)!=64 || $2 ~ /[^0-9a-f]/))) exit 1 }
    END { if(NR!=4) exit 1 }
    ' "$1" || fail 'Malformed rollback state; refusing silent bootstrap.'
    recorded_sequence=$(sed -n '3s/^sequence //p' "$1")
    recorded_digest=$(sed -n '4s/^sha256 //p' "$1")
}
write_replay_record() {
    printf 'conf-sshd-state-v1\nlist-id %s\nsequence %s\nsha256 %s\n' "$list_id" "$1" "$2" > "$3"
}
confirm_policy_change() {
    say "Signature policy change: $1; fingerprint $2; pin mode $3; list $4." >&2
    if [ "$3" = primary ]; then say 'Primary pin trusts valid, bound signing subkeys of that primary.' >&2
    else say 'Subkey pin trusts only that exact signing subkey, not its siblings.' >&2; fi
    say 'If local/Worker discovery fails, optional WKD and configured keyservers may receive the email/fingerprint and your IP.' >&2
    if [ "$dry_run" = yes ]; then fail 'Trust-changing dry runs do not enroll, query certificates or prompt; rerun locally without --dry-run to review and consent.'; fi
    if ! ( : < /dev/tty ) 2>/dev/null; then fail 'Trust changes require confirmation in a local terminal (/dev/tty); no noninteractive bypass exists.'; fi
    printf 'To confirm %s, type the complete fingerprint %s: ' "$1" "$2" > /dev/tty
    IFS= read -r confirmation < /dev/tty || fail 'Trust confirmation was not received.'
    [ "$confirmation" = "$2" ] || fail 'Trust change was not confirmed.'
}
require_explicit_installer() {
    if [ "$mode" != install ] && [ -f "$target_script" ]; then
        [ "$(grep -Fxc '# conf-sshd-client-security-v1' "$target_script" || :)" = 1 ] || fail 'Existing scheduled script predates signature enforcement; use --install to upgrade it before changing trust.'
    fi
    # --install or explicit trust options are a user-triggered installation;
    # scheduled -o without options never enters this policy-change flow.
    say 'Installer bootstrap code is trusted by this invocation. Independently checking a local script hash is recommended.' >&2
}
prepare_install_config() {
    config_prepared=yes
    staged_replay=
    replay_snapshot=absent
    staged_trust=
    old_policy=$policy
    old_pin=$pinned_fingerprint
    old_pin_mode=$pin_mode
    old_list=$list_id
    if [ "$config_snapshot" = absent ]; then
        requested_verification=${requested_verification:-$DEFAULT_GPG_VERIFY}
        requested_fingerprint=${requested_fingerprint:-$DEFAULT_GPG_FINGERPRINT}
        requested_pin_mode=${requested_pin_mode:-$DEFAULT_GPG_PIN_MODE}
        requested_list_id=${requested_list_id:-$DEFAULT_LIST_ID}
        requested_email=${requested_email:-$DEFAULT_GPG_EMAIL}
    fi
    if [ -n "$requested_email" ]; then gpg_email=$requested_email; fi
    if [ -n "$requested_keyservers" ]; then keyservers=$(printf '%s' "$requested_keyservers"); fi
    validate_discovery_settings
    if [ "$requested_verification" = off ]; then
        if [ "$old_policy" = required ]; then
            require_explicit_installer
            confirm_policy_change disable "$old_pin" "$old_pin_mode" "$old_list"
        fi
        policy=off
        # Preserve the enrolled pin and rollback state for any future re-enable.
        if [ "$old_pin" = - ]; then pinned_fingerprint=-; list_id=-; pin_mode=primary; fi
    elif [ "$requested_verification" = on ] || [ -n "$public_key_file$requested_fingerprint$requested_list_id$requested_min_sequence$requested_pin_mode" ]; then
        require_explicit_installer
        if [ "$old_pin" != - ]; then
            requested_fingerprint=${requested_fingerprint:-$old_pin}
            requested_list_id=${requested_list_id:-$old_list}
        fi
        if [ -z "$requested_fingerprint" ] || [ -z "$requested_list_id" ]; then
            fail 'Enabling verification requires --gpg-fingerprint and --list-id (or configured defaults).'
        fi
        requested_pin_mode=${requested_pin_mode:-$pin_mode}
        case $requested_pin_mode in primary|subkey) : ;; *) fail '--gpg-pin-mode must be primary or subkey.' ;; esac
        requested_fingerprint=$(printf '%s' "$requested_fingerprint" | tr 'a-f' 'A-F')
        printf '%s\n' "$requested_fingerprint" | grep -Eq '^[0-9A-F]{40}$' || fail 'Expected a full 40-hex fingerprint.'
        printf '%s\n' "$requested_list_id" | grep -Eq '^[A-Za-z0-9._-]{1,64}$' || fail 'Invalid signed list ID.'
        [ "$requested_list_id" != - ] || fail 'List ID cannot be a dash.'
        if [ "$old_pin" != - ]; then
            [ "$requested_list_id" = "$old_list" ] || fail 'Reinstall cannot reset the enrolled list identity or rollback history.'
            [ -f "$replay_state" ] || fail 'Rollback state is missing after enrollment; refusing silent bootstrap.'
        fi
        confirm_policy_change enable/change "$requested_fingerprint" "$requested_pin_mode" "$requested_list_id"
        policy=required
        list_id=$requested_list_id
        pinned_fingerprint=$requested_fingerprint
        pin_mode=$requested_pin_mode
        need date
        discover_certificate
        if [ "$old_pin" != - ] && [ -n "$requested_min_sequence" ]; then
            floor=$requested_min_sequence
            if printf '%s\n' "$floor" | grep -Eq '^[1-9][0-9]{0,9}$' && [ "$floor" -le 2147483647 ]; then :
            else fail 'Minimum sequence must be 1..2147483647.'; fi
            new_temp "$state"; replay_snapshot=$TEMP
            cp "$replay_state" "$replay_snapshot"
            read_replay_state "$replay_snapshot"
            [ "$floor" -ge "$recorded_sequence" ] || fail 'Explicit minimum sequence cannot lower the persisted rollback boundary.'
            new_temp "$state"; staged_replay=$TEMP
            if [ "$floor" -gt "$recorded_sequence" ]; then write_replay_record "$((floor - 1))" - "$staged_replay"
            else cp "$replay_snapshot" "$staged_replay"; fi
        fi
        if [ "$old_pin" = - ]; then
            if [ -e "$replay_state" ] || [ -e "$pending_state" ] || [ -e "$pending_bundle" ]; then
                fail 'Existing security state requires manual recovery; cannot silently enroll over it.'
            fi
            floor=${requested_min_sequence:-1}
            if printf '%s\n' "$floor" | grep -Eq '^[1-9][0-9]{0,9}$' && [ "$floor" -le 2147483647 ]; then :
            else fail 'Minimum sequence must be 1..2147483647.'; fi
            new_temp "$state"; staged_replay=$TEMP
            write_replay_record "$((floor - 1))" - "$staged_replay"
        fi
    fi
    if [ "$policy" = required ] && [ -z "$staged_trust" ]; then
        require_explicit_installer
        confirm_policy_change reinstall/refresh "$pinned_fingerprint" "$pin_mode" "$list_id"
        discover_certificate
    fi
    if [ -n "$primary_url" ] || [ -n "$fallback_urls_file" ]; then
        new_temp "$state"; new_urls=$TEMP
        if [ -n "$primary_url" ]; then printf '%s\n' "$primary_url" > "$new_urls"
        else sed -n '1p' "$urls" > "$new_urls"; fi
        if [ -n "$fallback_urls_file" ]; then
            check_path "$fallback_urls_file" file
            [ -f "$fallback_urls_file" ] || fail 'Fallback URL file does not exist.'
            [ "$(wc -c < "$fallback_urls_file" | tr -d ' ')" -le 35000 ] || fail 'Fallback URL file is too large.'
            if [ -s "$fallback_urls_file" ]; then strict_text "$fallback_urls_file"; fi
            cat "$fallback_urls_file" >> "$new_urls"
        elif [ -n "$primary_url" ]; then sed -n '2,$p' "$urls" >> "$new_urls"; fi
        urls=$new_urls
        validate_urls "$urls"
    fi
    new_temp "$state"; staged_config=$TEMP
    printf 'conf-sshd-local-v1\npolicy %s\nlist-id %s\nfingerprint %s\npin-mode %s\nemail %s\n' "$policy" "$list_id" "$pinned_fingerprint" "$pin_mode" "$gpg_email" > "$staged_config"
    sed 's/^/url /' "$urls" >> "$staged_config"
    sed 's/^/keyserver /' "$server_list" >> "$staged_config"
}
commit_install_config() {
    if [ -n "$staged_trust" ]; then replace_file "$trust_key" "$staged_trust" 600; fi
    if [ -n "$staged_replay" ]; then replace_file "$replay_state" "$staged_replay" 600 "$replay_snapshot"; fi
    replace_file "$local_config" "$staged_config" 600 "$config_snapshot"
}
validate_signed_document() {
    last_lf "$response" || fail 'Signed document must end with LF.'
    [ "$(wc -c < "$response" | tr -d ' ')" -le 1048576 ] || fail 'Signed document exceeds 1 MiB.'
    new_temp "$state"; invalid_bytes=$TEMP
    tr -d '\012\040-\176' < "$response" > "$invalid_bytes"
    [ ! -s "$invalid_bytes" ] || fail 'Signed document contains noncanonical bytes.'
    new_temp "$state"; metadata=$TEMP
    awk '
    NR==1 { if($0!="# conf-sshd-signed-v1") exit 1 }
    NR==2 { if($0!="# list-id " $3 || $3 ~ /[^A-Za-z0-9._-]/ || length($3)<1 || length($3)>64) exit 1; print $3 }
    NR==3 { if($0!="# sequence " $3 || $3 !~ /^[1-9][0-9]*$/ || length($3)>10 || $3+0>2147483647) exit 1; print $3 }
    NR==4 || NR==5 { label=(NR==4 ? "issued-at" : "expires-at")
      if($0!="# " label " " $3 || $3 !~ /^(0|[1-9][0-9]*)$/ || length($3)>10) exit 1
      if(NR==4) issue=$3+0; else if($3+0<=issue) exit 1; print $3 }
    NR==6 { if($0!="# revoke yes" && $0!="# revoke no") exit 1; revoke=$3; print $3 }
    NR==7 { if($0!="# key-count " $3 || $3 !~ /^(0|[1-9][0-9]*)$/ || length($3)>4 || $3+0>1000) exit 1
      if(($3==0 && revoke!="yes") || ($3!=0 && revoke!="no")) exit 1; print $3 }
    NR==8 { if($0!="# end-metadata") exit 1 }
    END { if(NR<8) exit 1 }
    ' "$response" > "$metadata" || fail 'Invalid signed-document schema or revocation metadata.'
    release_list=$(sed -n '1p' "$metadata")
    sequence=$(sed -n '2p' "$metadata")
    issued_at=$(sed -n '3p' "$metadata")
    expires_at=$(sed -n '4p' "$metadata")
    key_count=$(sed -n '6p' "$metadata")
    revision=$sequence
    new_temp "$state"; payload=$TEMP
    tail -n +9 "$response" > "$payload"
    [ "$(wc -l < "$payload" | tr -d ' ')" = "$key_count" ] || fail 'Signed payload key count mismatch.'
    # Signed documents are canonical even when signature verification is OFF.
    awk 'NF!=2 || $0!=$1 " " $2 {exit 1}' "$payload" || fail 'Signed document key lines must be comment-free and canonical.'
    if [ "$policy" = required ]; then
        [ "$release_list" = "$list_id" ] || fail 'Signed list identity does not match local enrollment.'
        now=$(date +%s)
        if [ "$enforce_freshness" = yes ]; then
            if [ "$issued_at" -le "$((now + 300))" ] && [ "$expires_at" -gt "$now" ]; then :
            else fail 'Signed release is expired or issued too far in the future.'; fi
        fi
    fi
    digest=$(sha256 "$response")
    validate_payload
}
verify_signature() {
    last_lf "$signature" || fail 'Detached signature must end with LF.'
    [ "$(wc -c < "$signature" | tr -d ' ')" -le 65536 ] || fail 'Detached signature exceeds 64 KiB.'
    new_temp "$state"; bad_signature=$TEMP
    tr -d '\012\040-\176' < "$signature" > "$bad_signature"
    [ ! -s "$bad_signature" ] || fail 'Detached signature must be ASCII armor with LF line endings.'
    awk '
    NR==1 {if($0!="-----BEGIN PGP SIGNATURE-----") exit 1}
    { if(ended) exit 1; if($0=="-----END PGP SIGNATURE-----") ended=1 }
    END {if(!ended) exit 1}
    ' "$signature" || fail 'Malformed detached-signature armor.'
    new_temp "$state"; gpg_status=$TEMP
    gpg_local --status-fd 1 --verify "$signature" "$response" > "$gpg_status" 2>/dev/null || fail 'Detached signature verification failed.'
    awk -v pin="$pinned_fingerprint" -v mode="$pin_mode" -v expectedprimary="$certificate_primary" -v now="$(date +%s)" '
    $1!="[GNUPG:]" {bad=1}
    $2 ~ /^(BADSIG|ERRSIG|NO_PUBKEY|EXPSIG|EXPKEYSIG|REVKEYSIG|KEYEXPIRED|KEYREVOKED|SIGEXPIRED|BADARMOR|FAILURE|ERROR|NODATA|UNEXPECTED)$/ {bad=1}
    $2=="VALIDSIG" { good++; primary=$12
      if(NF!=12 || $7!=4 || $11!="00" || length(primary)!=40 || primary ~ /[^0-9A-F]/ || primary!=expectedprimary || (mode=="primary" && primary!=pin) || (mode=="subkey" && $3!=pin) || length($3)!=40 || $3 ~ /[^0-9A-F]/ || ($10!=8 && $10!=9 && $10!=10)) bad=1
      if($5 !~ /^(0|[1-9][0-9]*)$/ || length($5)>10 || $5+0>now+300 || $6 !~ /^(0|[1-9][0-9]*)$/ || length($6)>10 || ($6!=0 && $6+0<=now)) bad=1 }
    END {if(bad || good!=1) exit 1}
    ' "$gpg_status" || fail 'Signature status lacks one valid, unexpired signature from the locally pinned primary/subkey.'
    actual_signer=$(awk '$2=="VALIDSIG" {print $3}' "$gpg_status")
    actual_primary=$(awk '$2=="VALIDSIG" {print $12}' "$gpg_status")
}
check_replay() {
    [ "$sequence" -ge "$recorded_sequence" ] || fail 'Signed sequence rollback rejected.'
    if [ "$sequence" = "$recorded_sequence" ]; then
        [ "$digest" = "$recorded_digest" ] || fail 'Signed sequence equivocation rejected (same sequence, different bytes).'
    fi
}
validate_response() {
    if [ "$policy" = required ]; then
        verify_signature
        validate_signed_document
        check_replay
    elif [ "$(sed -n '1p' "$response")" = '# conf-sshd-signed-v1' ]; then
        validate_signed_document
    else validate_legacy_response; fi
}
# Journal pairs are local only; transport is /ssh.keys plus /ssh.keys.sig.
make_pending_bundle() {
    cat "$response" > "$1"
    printf '# detached-signature\n' >> "$1"
    cat "$signature" >> "$1"
}
read_pending_bundle() {
    [ "$(wc -c < "$pending_bundle" | tr -d ' ')" -le 1114133 ] || fail 'Pending package is oversized.'
    new_temp "$state"; response=$TEMP
    new_temp "$state"; signature=$TEMP
    # Marker is forbidden by the strict document schema and signature armor.
    awk -v sig="$signature" '
    $0=="# detached-signature" {if(found++) exit 1; next}
    {if(found) print > sig; else print}
    END {if(found!=1) exit 1}
    ' "$pending_bundle" > "$response" || fail 'Malformed pending package.'
    # Enforce original bytes: awk must not normalize a malformed journal.
    new_temp "$state"; rebuilt=$TEMP
    make_pending_bundle "$rebuilt"
    cmp -s "$rebuilt" "$pending_bundle" || fail 'Noncanonical pending package.'
}
check_audit_paths() {
    check_path "$audit_dir" dir
    check_path "$audit_dir/current" file
    check_path "$audit_dir/previous" file
    for audit_slot_name in a b; do
        check_path "$audit_dir/$audit_slot_name" dir
        for audit_name in ssh.keys ssh.keys.sig metadata; do
            check_path "$audit_dir/$audit_slot_name/$audit_name" file
        done
    done
}
read_audit_pointer() {
    pointer_slot=
    pointer_snapshot=absent
    if [ -f "$1" ]; then
        new_temp "$state"; pointer_snapshot=$TEMP
        cp "$1" "$pointer_snapshot"
        [ "$(wc -c < "$pointer_snapshot" | tr -d ' ')" = 34 ] || fail 'Malformed audit pointer.'
        awk 'NR==1 {if($0!="conf-sshd-audit-pointer-v1") exit 1} NR==2 {if($0!="slot a" && $0!="slot b") exit 1} END {if(NR!=2) exit 1}' "$pointer_snapshot" || fail 'Malformed audit pointer.'
        last_lf "$pointer_snapshot" || fail 'Malformed audit pointer ending.'
        pointer_slot=$(sed -n '2s/^slot //p' "$pointer_snapshot")
    fi
}
audit_replace() {
    check_path "$1" file
    chmod 600 "$2"
    mv -f "$2" "$1"
}
audit_pointer() {
    new_temp "$audit_dir"; new_pointer=$TEMP
    printf 'conf-sshd-audit-pointer-v1\nslot %s\n' "$2" > "$new_pointer"
    audit_replace "$1" "$new_pointer"
}
prepare_audit_slot() {
    check_audit_paths
    if [ "$dry_run" = yes ]; then return; fi
    [ -d "$audit_dir" ] || mkdir "$audit_dir"
    chmod 700 "$audit_dir"
    read_audit_pointer "$audit_dir/current"
    audit_old_current=$pointer_slot
    audit_current_snapshot=$pointer_snapshot
    read_audit_pointer "$audit_dir/previous"
    audit_old_previous=$pointer_slot
    audit_previous_snapshot=$pointer_snapshot
    audit_base=${audit_old_current:-$audit_old_previous}
    if [ "$audit_base" = a ]; then audit_slot=b; else audit_slot=a; fi
    # This slot is about to be reused; stop advertising it as history first.
    if [ "$audit_old_previous" = "$audit_slot" ]; then
        check_expected_file "$audit_dir/previous" "$audit_previous_snapshot"
        rm -f "$audit_dir/previous"
        audit_previous_snapshot=absent
    fi
    [ -d "$audit_dir/$audit_slot" ] || mkdir "$audit_dir/$audit_slot"
    chmod 700 "$audit_dir/$audit_slot"
    new_temp "$audit_dir/$audit_slot"; audit_document=$TEMP
    cp "$response" "$audit_document"
    new_temp "$audit_dir/$audit_slot"; audit_signature=$TEMP
    cp "$signature" "$audit_signature"
    audit_replace "$audit_dir/$audit_slot/ssh.keys" "$audit_document"
    audit_replace "$audit_dir/$audit_slot/ssh.keys.sig" "$audit_signature"
}
invalidate_audit_current() {
    if [ "$dry_run" = yes ]; then return; fi
    check_audit_paths
    [ -d "$audit_dir" ] || return 0
    if [ "$policy" != required ]; then
        read_audit_pointer "$audit_dir/current"
        audit_old_current=$pointer_slot
        audit_current_snapshot=$pointer_snapshot
        read_audit_pointer "$audit_dir/previous"
        audit_previous_snapshot=$pointer_snapshot
    fi
    check_expected_file "$audit_dir/current" "$audit_current_snapshot"
    check_expected_file "$audit_dir/previous" "$audit_previous_snapshot"
    if [ -n "$audit_old_current" ]; then
        audit_pointer "$audit_dir/previous" "$audit_old_current"
        rm -f "$audit_dir/current"
    fi
}
publish_audit_slot() {
    if [ "$dry_run" = yes ]; then say 'Would publish the verified original key document and detached signature to the bounded local audit.'; return; fi
    check_audit_paths
    if cmp -s "$response" "$audit_dir/$audit_slot/ssh.keys" && cmp -s "$signature" "$audit_dir/$audit_slot/ssh.keys.sig"; then :
    else fail 'Audit staging changed; current audit remains uncommitted.'; fi
    new_temp "$audit_dir/$audit_slot"; audit_metadata=$TEMP
    printf 'conf-sshd-audit-v1\ninstalled-at %s\nclient-version conf-sshd-client-security-v1\nlist-id %s\nsequence %s\nsource %s\nsigner-fingerprint %s\nprimary-fingerprint %s\npin-mode %s\npinned-fingerprint %s\ndocument-sha256 %s\nsignature-sha256 %s\n' \
        "$(date +%s)" "$list_id" "$sequence" "$accepted_source" "$actual_signer" "$actual_primary" "$pin_mode" "$pinned_fingerprint" "$digest" "$(sha256 "$signature")" > "$audit_metadata"
    audit_replace "$audit_dir/$audit_slot/metadata" "$audit_metadata"
    check_expected_file "$audit_dir/current" absent
    audit_pointer "$audit_dir/current" "$audit_slot"
}
write_pending_source() {
    new_temp "$state"; source_record=$TEMP
    printf 'conf-sshd-pending-source-v1\nsequence %s\ndocument-sha256 %s\nsignature-sha256 %s\nsource %s\n' \
        "$sequence" "$digest" "$(sha256 "$signature")" "$accepted_source" > "$source_record"
    replace_file "$pending_source" "$source_record" 600
}
read_pending_source() {
    accepted_source=local-pending:original-source-unavailable
    if [ ! -f "$pending_source" ]; then return; fi
    [ "$(wc -c < "$pending_source" | tr -d ' ')" -le 2400 ] || fail 'Pending source context is oversized.'
    strict_text "$pending_source"
    awk -v seq="$sequence" -v doc="$digest" -v sig="$(sha256 "$signature")" '
    NR==1 {if($0!="conf-sshd-pending-source-v1") exit 1}
    NR==2 {if($0!="sequence " seq) exit 1}
    NR==3 {if($0!="document-sha256 " doc) exit 1}
    NR==4 {if($0!="signature-sha256 " sig) exit 1}
    NR==5 {if(substr($0,1,7)!="source " || length($0)<8) exit 1}
    END {if(NR!=5) exit 1}
    ' "$pending_source" || fail 'Pending source context does not match its exact verified package.'
    accepted_source=$(sed -n '5s/^source //p' "$pending_source")
    if [ "$accepted_source" != local-pending:original-source-unavailable ]; then
        validate_url "$accepted_source" || fail 'Pending audit source is not a configured-format HTTPS URL.'
    fi
}

finish_verified_release() {
    if [ "$auth_prepared" = no ]; then prepare_authorized_keys; fi
    # Commit a complete verified package before advancing any anti-rollback state
    # or replacing keys. Atomic renames survive process interruption, not every
    # power-loss/filesystem failure; no portable fsync promise is made here.
    if [ "$dry_run" = no ]; then
        if [ "$replace_pending" = yes ]; then
            # Preserve the authenticated old journal floor before superseding its
            # files. A crash at any step can only retain/raise this boundary.
            new_temp "$state"; promoted_state=$TEMP
            write_replay_record "$recorded_sequence" "$recorded_digest" "$promoted_state"
            replace_file "$replay_state" "$promoted_state" 600
            rm -f "$pending_state" "$pending_bundle" "$pending_source"
        fi
        if [ ! -f "$pending_state" ]; then
            new_temp "$state"; pending_tmp=$TEMP
            make_pending_bundle "$pending_tmp"
            replace_file "$pending_bundle" "$pending_tmp" 600
            write_pending_source
            new_temp "$state"; pending_record=$TEMP
            write_replay_record "$sequence" "$digest" "$pending_record"
            replace_file "$pending_state" "$pending_record" 600 absent
        fi
    fi
    prepare_audit_slot
    invalidate_audit_current
    commit_authorized_keys
    if [ "$dry_run" = no ]; then
        new_temp "$state"; final_state=$TEMP
        write_replay_record "$sequence" "$digest" "$final_state"
        replace_file "$replay_state" "$final_state" 600
        publish_audit_slot
        rm -f "$pending_state" "$pending_bundle" "$pending_source"
    else publish_audit_slot; fi
}
sync_keys() {
    need ssh-keygen
    validate_build
    if [ "$policy" = required ]; then
        need date
        if [ -n "${staged_replay:-}" ]; then read_replay_state "$staged_replay"
        else read_replay_state "$replay_state"; fi
        if [ -z "$gpg_home" ]; then import_pinned_key "$trust_key"; fi
        if [ -f "$pending_state" ] || [ -f "$pending_bundle" ]; then
            saved_sequence=$recorded_sequence
            saved_digest=$recorded_digest
            pending_sequence=
            pending_digest=
            if [ -f "$pending_state" ]; then
                read_replay_state "$pending_state"
                pending_sequence=$recorded_sequence
                pending_digest=$recorded_digest
                [ "$pending_digest" != - ] || fail 'Pending state must identify an already verified document.'
                [ "$pending_sequence" -ge "$saved_sequence" ] || fail 'Pending rollback record is below the committed boundary.'
                if [ "$pending_sequence" = "$saved_sequence" ]; then
                    [ "$pending_digest" = "$saved_digest" ] || fail 'Pending rollback record conflicts with committed history.'
                fi
            fi
            recorded_sequence=$saved_sequence
            recorded_digest=$saved_digest
            if [ -f "$pending_bundle" ]; then
                read_pending_bundle
                enforce_freshness=no
                validate_signed_document
                enforce_freshness=yes
                check_replay
                if [ -n "$pending_sequence" ]; then
                    if [ "$sequence" != "$pending_sequence" ] || [ "$digest" != "$pending_digest" ]; then
                        fail 'Pending package does not match its rollback record.'
                    fi
                elif [ "$sequence" = "$recorded_sequence" ] && [ "$digest" = "$recorded_digest" ]; then
                    # Crash while removing an old journal after promoting its
                    # floor: committed state already authenticates these bytes.
                    pending_sequence=$sequence
                    pending_digest=$digest
                fi
                if ( lock_owned=no; created_state=no; created_ssh=no; temps=; child_result=0
                     trap 'child_result=$?; gpg_home=; cleanup "$child_result"' 0
                     validate_response ); then
                    # Subshell checks do not propagate machine-status fields.
                    verify_signature
                    read_pending_source
                    if [ "$validation_only" = no ]; then
                        finish_verified_release
                        say 'Recovered the same verified pending release; no fallback was fetched.'
                    fi
                    return
                fi
                [ -n "$pending_sequence" ] || fail 'Uncommitted pending package is no longer verifiable; manual recovery is required.'
            else
                [ -n "$pending_sequence" ] || fail 'Pending package/state is incomplete.'
            fi
            # The protected committed journal records a previously verified
            # release. Its current expiry/revocation never authorizes installing
            # it, but its sequence/digest still prevent rollback while fetching
            # a fresh valid release under the currently enrolled pin.
            recorded_sequence=$pending_sequence
            recorded_digest=$pending_digest
            replace_pending=yes
            say 'Pending release cannot currently be applied; retaining its rollback floor while fetching a fresh valid release.' >&2
        fi
    fi
    new_temp "$state"; response=$TEMP
    new_temp "$state"; signature=$TEMP
    accepted=no
    # Five total attempts per local endpoint. Each attempt shares one 30-second
    # body/signature budget; only retrieval failures use the 1/3/8/12s backoff.
    # Worker upstream fallback remains separate and does not multiply this loop.
    need date
    need sleep
    while IFS= read -r source_url; do
        source_attempt=1
        while [ "$source_attempt" -le 5 ]; do
            attempt_started=$(date +%s)
            attempt_deadline=$((attempt_started + 30))
            source_failure=retrieval
            if download "$source_url" "$response" 1048576 30; then
                # Reject malformed/replayed/expired bodies before a signature
                # retrieval failure could disguise them as retryable transport.
                if ! ( lock_owned=no; lock_reclaim_owned=no; created_state=no; created_ssh=no; temps=; child_result=0
                       trap 'child_result=$?; gpg_home=; cleanup "$child_result"' 0
                       if [ "$policy" = required ]; then validate_signed_document; check_replay
                       elif [ "$(sed -n '1p' "$response")" = '# conf-sshd-signed-v1' ]; then validate_signed_document
                       else validate_legacy_response; fi ); then
                    source_failure=validation
                elif [ "$policy" = required ]; then
                    remaining=$((attempt_deadline - $(date +%s)))
                    # A backwards wall-clock adjustment must not extend this
                    # request past the original maximum per-request timeout.
                    if [ "$remaining" -gt 30 ]; then remaining=30; fi
                    if [ "$remaining" -gt 0 ] && download "$source_url.sig" "$signature" 65536 "$remaining"; then
                        source_failure=none
                    elif [ "$remaining" -gt 0 ]; then source_failure=$download_failure; fi
                else source_failure=none; fi
            else source_failure=$download_failure; fi
            if [ "$source_failure" = none ]; then
                if ( lock_owned=no; lock_reclaim_owned=no; created_state=no; created_ssh=no; temps=; child_result=0
                     # Preserve the caller keyring but never delete it here.
                     trap 'child_result=$?; gpg_home=; cleanup "$child_result"' 0
                     validate_response ); then accepted=yes; accepted_source=$source_url; break; fi
                source_failure=validation
            fi
            if [ "$source_failure" != retrieval ] || [ "$source_attempt" -ge 5 ]; then break; fi
            case $source_attempt in 1) retry_delay=1 ;; 2) retry_delay=3 ;; 3) retry_delay=8 ;; 4) retry_delay=12 ;; esac
            say "Retrieval attempt $source_attempt/5 failed for $source_url; retrying in ${retry_delay}s." >&2
            sleep "$retry_delay"
            source_attempt=$((source_attempt + 1))
        done
        [ "$accepted" = no ] || break
        say "Rejected source $source_url; trying next locally configured source." >&2
    done < "$urls"
    [ "$accepted" = yes ] || fail 'No locally configured source passed the required policy; existing keys are unchanged.'
    validate_response
    if [ "$validation_only" = no ]; then
        if [ "$policy" = required ]; then finish_verified_release; else apply_payload; fi
    fi
}

if [ "$mode" = uninstall ] || { [ "$mode" = sync ] && [ "$cron_requested" = yes ] && [ "$cron_value" = false ] && [ -z "$root_password" ]; }; then
    policy=off
    config_snapshot=absent
else load_local_config; fi
case $mode in
    uninstall)
        if cron_present; then prepare_cron; apply_cron false; fi
        for uninstall_file in "$target_script" "$target_script.conf-sshd.bak"; do
            check_path "$uninstall_file" file
            if [ "$dry_run" = yes ]; then say "Would remove $uninstall_file"; else rm -f "$uninstall_file"; fi
        done
        say 'Uninstalled managed scheduling/script. Authorized keys, trust and rollback state are preserved.' ;;
    sync|keys|install)
        script_tmp=
        if [ "$mode" = sync ] && [ "$cron_requested" = yes ] && [ "$cron_value" = false ] && [ -z "$root_password" ]; then
            if cron_present; then prepare_cron; apply_cron false
            else say 'crontab is not installed; no managed schedule was changed.'; fi
            exit 0
        fi
        validate_build
        if [ "$mode" = install ] || [ "$trust_options" = yes ] || { [ "$config_snapshot" = absent ] && [ "$DEFAULT_GPG_VERIFY" = on ]; }; then
            prepare_install_config
        fi
        if [ "$mode" = install ] || { [ "$cron_requested" = yes ] && [ "$cron_value" != false ] && [ ! -f "$target_script" ]; }; then
            prepare_script
        fi
        # Only client prerequisites may bootstrap before key verification. Trust
        # consent has already happened; daemon/config/key writes remain staged.
        ensure_ssh_client
        validation_only=yes
        sync_keys
        prepare_authorized_keys
        if [ "$mode" != keys ]; then ensure_sshd; fi
        if [ "$cron_requested" = yes ]; then
            if [ "$cron_value" != false ]; then ensure_cron; fi
            if cron_present; then
                prepare_cron
                cron_prepared=yes
                if [ -z "$cron_value" ]; then cron_value=${existing_schedule:-$DEFAULT_CRON}; fi
            elif [ "$dry_run" = yes ]; then
                say 'Would inspect the existing crontab and configure scheduling after cron is installed.'
            fi
        fi
        if [ -n "$root_password" ]; then prepare_sshd_config; fi
        # Activate policy only after replacing any legacy scheduled executable.
        if [ -n "$script_tmp" ]; then install_script; fi
        if [ "$config_prepared" = yes ]; then commit_install_config; fi
        if [ "$policy" = required ]; then finish_verified_release; else apply_payload; fi
        if [ -n "$root_password" ]; then commit_sshd_config; fi
        if [ "$cron_prepared" = yes ]; then apply_cron "$cron_value"; fi ;;
esac
