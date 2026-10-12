#!/bin/sh
# conf-sshd-script-v2
# Generated configuration. Never source or eval downloaded data.
BASE_URL='@@BASE_URL@@'
DEFAULT_CRON='@@DEFAULT_CRON@@'

set -eu
umask 077
LC_ALL=C
export LC_ALL
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
temps=
lock_owned=no
created_state=no
created_ssh=no

say() { printf '%s\n' "$*"; }
fail() { printf 'conf-sshd: %s\n' "$*" >&2; exit 1; }
usage() {
    cat <<'HELP'
Usage: sh conf-sshd.sh [options]
  (no options), -o, --only-update-keys  Validate and sync managed public keys only
  -c, --cron ["five fields"|false]     Sync and schedule; bare -c keeps an existing
                                      schedule, otherwise the configured default.
                                      -c false only removes this script's schedule.
  -u, --update-self                    Explicitly update the installed script only
  --uninstall                         Remove own schedule/script; preserve keys/config
  -p, --allow-root-passwd yes|no       Explicit root-only sshd_config edit; never reload
  -n, --no-install-sshd                Compatibility flag; packages are never installed
  --dry-run                           Validate and show changes without applying them
  --status                            Show local installation and schedule status
  -h, --help                          Show this help

-u, --uninstall, -p and --status are exclusive operations. -o cannot use -c or -p.
Requires curl, ssh-keygen, awk, standard POSIX tools, mktemp, stat, and one of
sha256sum, shasum or openssl. Scheduling also requires crontab. Downloads require
HTTPS; existing keys survive any validation/download failure.
No SSH service is installed, restarted, or reloaded. Keep recovery access ready.
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
        --uninstall) select_mode uninstall ;;
        --status) select_mode status ;;
        -p|--allow-root-passwd)
            select_mode config
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
[ "$cron_requested" = no ] || [ "$mode" = sync ] || fail '-c cannot be combined with this operation.'

need() { command -v "$1" >/dev/null 2>&1 || fail "Missing dependency: $1. Install it explicitly before continuing."; }
for dep in awk cat chmod cmp cp dd grep id mkdir mktemp mv od rm rmdir sed stat tail tr wc; do need "$dep"; done
uid=$(id -u)
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

# GNU/Linux and BSD/macOS stat. No filesystem changes precede ownership checks.
if stat -c '%u %a %h' "$HOME" >/dev/null 2>&1; then
    stat_info() { stat -c '%u %a %h' "$1"; }
else
    stat_info() { stat -f '%u %Lp %l' "$1"; }
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
    result=$?
    trap - 0 HUP INT TERM
    old_ifs=$IFS; IFS='
'
    for path in $temps; do rm -f "$path"; done
    IFS=$old_ifs
    if [ "$lock_owned" = yes ]; then rm -f "$state/lock/pid"; rmdir "$state/lock" 2>/dev/null || :; fi
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
if [ "$dry_run" = no ]; then chmod 700 "$state"; fi
trap cleanup 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
if mkdir "$state/lock" 2>/dev/null; then
    lock_owned=yes; printf '%s\n' "$$" > "$state/lock/pid"
else
    fail "Another run holds $state/lock. If it is stale, verify the recorded process before removing that directory."
fi

# Inputs are origin-only build constants; also reject unbuilt or corrupted scripts.
validate_build() {
    printf '%s\n' "$BASE_URL" | grep -Eq '^https://([A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:]+\])(:[0-9]{1,5})?$' || fail 'BASE_URL must be a configured HTTPS origin.'
    validate_cron "$DEFAULT_CRON" >/dev/null || fail 'Invalid or unbuilt default cron configuration.'
}
download() {
    need curl
    # No redirects: a configured origin must serve these endpoints directly.
    curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
        --connect-timeout 10 --max-time 30 --retry 2 --retry-delay 1 \
        --retry-max-time 65 --max-filesize 1048576 --output "$2" "$1" || fail "Download failed: $1 (existing files unchanged)."
    [ "$(wc -c < "$2" | tr -d ' ')" -le 1048576 ] || fail 'Downloaded response is too large.'
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
    sh -n "$1" || fail 'Downloaded script has invalid shell syntax.'
    [ "$(grep -Fxc '# conf-sshd-script-v2' "$1" || :)" = 1 ] || fail 'Downloaded script is missing its unique version marker.'
    [ "$(grep -Fxc "BASE_URL='$BASE_URL'" "$1" || :)" = 1 ] || fail 'Downloaded script changed its configured origin.'
    [ "$(grep -Fxc "DEFAULT_CRON='$DEFAULT_CRON'" "$1" || :)" = 1 ] || fail 'Downloaded script has invalid default cron configuration.'
    if grep -Eq '@@[A-Z_]+@@' "$1"; then fail 'Downloaded script contains unexpanded build tokens.'; fi
}
install_script() {
    validate_build
    new_temp "$state"; script_tmp=$TEMP
    # In a piped invocation $0 can name an unrelated cwd file. Always fetch the
    # configured origin, rather than guessing whether $0 is this script.
    download "$BASE_URL/script.sh" "$script_tmp"
    validate_script "$script_tmp"
    replace_file "$target_script" "$script_tmp" 700
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

sync_keys() {
    need ssh-keygen
    validate_build
    new_temp "$state"; response=$TEMP
    download "$BASE_URL/ssh.keys" "$response"
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
    awk '
    {
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
    if [ "$auth_snapshot" != absent ] && cmp -s "$auth_snapshot" "$new_auth"; then
        if [ "$dry_run" = no ]; then chmod 600 "$auth_file"; fi
        say "Keys unchanged ($key_count keys, revision $revision)."
    else
        replace_file "$auth_file" "$new_auth" 600 "$auth_snapshot"
        say "Validated $key_count keys at revision $revision."
    fi
}

edit_sshd_config() {
    [ "$uid" = 0 ] || fail '-p requires root.'
    need sshd
    config=/etc/ssh/sshd_config
    check_path /etc/ssh dir
    check_path "$config" file
    [ -f "$config" ] || fail 'sshd_config does not exist; install/configure sshd yourself first.'
    new_temp /etc/ssh; config_snapshot=$TEMP
    cp "$config" "$config_snapshot"
    # Editing a global directive cannot reliably predict Include/Match overrides.
    if awk '
        { name=$0; sub(/^[[:space:]]*/,"",name)
          if(substr(name,1,1)=="\"") { name=substr(name,2); sub(/\".*$/,"",name) }
          else sub(/[[:space:]=].*$/,"",name)
          name=tolower(name); if(name=="include" || name=="match") { found=1; exit }
        }
        END { exit !found }
    ' "$config_snapshot"; then
        fail 'sshd_config uses Include or Match. Review and change root-login policy manually; nothing changed.'
    fi
    sshd -t -f "$config" || fail 'Existing sshd_config is invalid.'
    new_temp /etc/ssh; config_tmp=$TEMP
    if [ "$root_password" = yes ]; then setting=yes; else setting=prohibit-password; fi
    awk -v value="$setting" '
    BEGIN { print "PermitRootLogin " value }
    { name=$0; sub(/^[[:space:]]*/,"",name)
      if(substr(name,1,1)=="\"") { name=substr(name,2); sub(/\".*$/,"",name) }
      else sub(/[[:space:]=].*$/,"",name)
      if(tolower(name)!="permitrootlogin") print
    }
    ' "$config_snapshot" > "$config_tmp"
    sshd -t -f "$config_tmp" || fail 'Staged sshd_config failed validation.'
    new_temp "$state"; effective=$TEMP
    sshd -T -f "$config_tmp" > "$effective" || fail 'Cannot evaluate staged sshd_config.'
    actual=$(awk '$1=="permitrootlogin" {print $2}' "$effective")
    case "$setting:$actual" in yes:yes|prohibit-password:prohibit-password|prohibit-password:without-password) : ;; *) fail 'Effective root-login policy does not match the requested setting.' ;; esac
    replace_file "$config" "$config_tmp" 600 "$config_snapshot"
    say 'Root-login policy validated. No service reload was performed; test recovery access before applying it.'
    [ "$root_password" != yes ] || say 'PermitRootLogin yes does not enable PasswordAuthentication if it is disabled elsewhere.'
}

case $mode in
    update)
        validate_build
        [ -f "$target_script" ] || fail 'No installed script. Install scheduling with -c first.'
        new_temp "$state"; updated_script=$TEMP
        download "$BASE_URL/script.sh" "$updated_script"
        validate_script "$updated_script"
        replace_file "$target_script" "$updated_script" 700
        say 'Script update validated. Keys, cron and sshd configuration were not changed.' ;;
    uninstall)
        if command -v crontab >/dev/null 2>&1; then prepare_cron; apply_cron false; fi
        for uninstall_file in "$target_script" "$target_script.conf-sshd.bak"; do
            check_path "$uninstall_file" file
            if [ "$dry_run" = yes ]; then say "Would remove $uninstall_file"; else rm -f "$uninstall_file"; fi
        done
        say 'Uninstalled managed scheduling/script. Authorized keys and sshd configuration are preserved.' ;;
    config) edit_sshd_config ;;
    sync|keys)
        if [ "$cron_requested" = yes ]; then
            prepare_cron
            if [ "$cron_value" = false ]; then apply_cron false; exit 0; fi
            validate_build
            if [ -z "$cron_value" ]; then cron_value=${existing_schedule:-$DEFAULT_CRON}; fi
        fi
        sync_keys
        if [ "$cron_requested" = yes ]; then install_script; apply_cron "$cron_value"; fi ;;
esac
