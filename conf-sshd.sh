#!/bin/bash
set -e
set -o pipefail

########## 一些配置 ##########

# 默认获取 SSH key 的地方，一般是 Github.
sshkey_url="{{ SSH_KEY_URL }}"
# 默认的 Cron 执行计划, 每天凌晨 0 点执行
default_cron="{{ DEFAULT_CRON }}"
# 脚本 Url
script_url="{{ SCRIPT_URL }}"

############ 脚本区 ##########

script_params=("$@")
has_param() {
    for param in "${script_params[@]}"; do
        for tParam in "$@"; do
            if [ "$tParam" == "$param" ]; then
                echo "true"
                return
            fi
        done
    done
    echo "false"
}

get_param_value() {
    local find=false
    for param in "${script_params[@]}"; do
        if [ "$find" == "true" ]; then
            if [[ $param == -* ]]; then
                return
            fi

            echo "$param" 
            return
        fi
        for tParam in "$@"; do
            if [ "$tParam" == "$param" ]; then
                find=true
                break
            fi
        done
    done
}

# 帮助信息.
if [ "$(has_param "-h" "--help")" == "true" ]; then
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -h, --help                          Print this help message."
    echo ""
    echo "Available to any user: "
    echo "  -c, --cron \"<cron> | false\"       Configure Crontab to automatically update ssh keys."
    echo "                                      Cron expression MUST be quoted (e.g., \"* 0 * * *\")."
    echo "                                      If 'false' is specified, Crontab settings will be deleted."
    echo ""
    echo "  -o, --only-update-keys            Only update SSH keys, do not configure ssh server."
    echo "  -u, --update-self                 Update this script to the latest version."
    echo "  --uninstall                       Uninstall this script (remove cron and local files)."
    echo ""
    echo "only available when the script is executed as root:"
    echo "  -n, --no-install-sshd             Do not install SSH Server."
    echo "  -p, --allow-root-passwd <yes | no>  Allow Root to log in with a password."
    echo ""
    exit 0
fi

update_sshkeys() {
    if [ "$sshkey_url" == "" ] || [[ "$sshkey_url" == "{{"* ]]; then
        echo "ERROR: sshkey_url is not configured."
        exit 1
    fi

    echo "Downloading SSH public key from '$sshkey_url'"
    mkdir -p ~/.ssh
    chmod 700 ~/.ssh

    local dl_tmp_file=~/.ssh/authorized_keys.dl.tmp
    if ! curl -sL "$sshkey_url" -o "$dl_tmp_file"; then 
        echo "Failed to download SSH public key at $(date '+%Y-m-d %H:%M:%S')"
        rm -f "$dl_tmp_file"
        exit 1
    fi

    if [ ! -s "$dl_tmp_file" ] || ! grep -qE "(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp)" "$dl_tmp_file"; then
        echo "Downloaded file is empty or does not contain valid SSH key types at $(date '+%Y-m-d %H:%M:%S')"
        echo "Aborting update to prevent lockout."
        rm -f "$dl_tmp_file"
        exit 1
    fi
    
    echo "-------------------- SSH Keys --------------------"
    cat "$dl_tmp_file"
    echo "--------------------------------------------------"
    
    local auth_file=~/.ssh/authorized_keys
    local new_auth_file=~/.ssh/authorized_keys.new.tmp
    
    # 受管理文本块标记
    local begin_marker="# --- BEGIN MANAGED BY CONF-SSHD SCRIPT ---"
    local end_marker="# --- END MANAGED BY CONF-SSHD SCRIPT ---"

    local managed_block_found=false
    local inside_managed_block=false

    touch "$auth_file"
    true > "$new_auth_file"

    # 逐行读取文件
    while IFS= read -r line; do
        if [ "$line" == "$begin_marker" ]; then
            managed_block_found=true
            inside_managed_block=true
            
            {
                echo "" # 确保和前面的内容有空行
                echo "$begin_marker"
                cat "$dl_tmp_file"
                echo "$end_marker"
            } >> "$new_auth_file"
            
        elif [ "$line" == "$end_marker" ]; then
            inside_managed_block=false
        elif [ "$inside_managed_block" == "false" ]; then
            echo "$line" >> "$new_auth_file"
        fi
    done < "$auth_file"

    if [ "$managed_block_found" == "false" ]; then
        {
            echo "" # 确保和前面的内容有空行
            echo "$begin_marker"
            cat "$dl_tmp_file"
            echo "$end_marker"
        } >> "$new_auth_file"
    fi

    mv "$new_auth_file" "$auth_file"
    rm -f "$dl_tmp_file"

    chmod 600 "$auth_file"
    echo "SSH public key updated successfully (managed block only) at $(date '+%Y-m-d %H:%M:%S')"
}

# 检查是否指定了 --uninstall
if [ "$(has_param "--uninstall")" == "true" ]; then
    echo "Uninstalling conf-sshd (disabling auto-updates)..."
    
    if [ "$(command -v crontab)" != "" ]; then
        echo "Removing Crontab entry..."
        (crontab -l 2>/dev/null || true | grep -v "conf-sshd.sh") | crontab -
    else
        echo "Crontab utility not found, skipping Crontab removal."
    fi

    script_dir="$HOME/.conf-sshd"
    if [ -d "$script_dir" ]; then
        echo "Removing script files from $script_dir..."
        rm -rf "$script_dir"
    else
        echo "Script directory $script_dir not found, skipping removal."
    fi

    echo "Uninstall complete."
    echo "Note: authorized_keys managed block and sshd_config were NOT affected."
    exit 0
fi

# 检查是否只更新密钥.
if [ "$(has_param "-o" "--only-update-keys")" == "true" ]; then
    update_sshkeys
    exit 0
fi

# 检查是否指定了 --update-self
if [ "$(has_param "-u" "--update-self")" == "true" ]; then
    echo "Updating conf-sshd script..."
    mkdir -p ~/.conf-sshd # 确保目录存在
    target_script=~/.conf-sshd/conf-sshd.sh

    if [ -f "$target_script" ]; then
        cp "$target_script" "$target_script.bak"
    fi

    # 下载到临时文件
    if ! curl -sL "$script_url" -o "$target_script.tmp"; then
         echo "Script download failed at $(date '+%Y-%m-%d %H:%M:%S')"
         rm -f "$target_script.tmp"
         exit 1
    fi

    mv "$target_script.tmp" "$target_script"

    chmod +x "$target_script"
    echo "Script updated successfully at $(date '+%Y-%m-%d %H:%M:%S')"
    exit 0
fi

# 检查 SSHD 是否安装.
if ! /usr/sbin/sshd -T > /dev/null 2>&1 && [ "$(has_param "-n" "--no-install-sshd")" == "false" ]; then
    if [ "$(id -u)" -eq 0 ]; then
        echo "The ssh server is not installed, and the script is executed as root, so it will be installed."
        if [ -f /etc/redhat-release ]; then
            yum install -y openssh-server
        elif [ -f /etc/debian_version ]; then
            apt-get update
            apt-get install -y openssh-server
        fi
        echo "The ssh server has been installed."
    else
        echo "The ssh server is not installed, but the script is executed as a non-root user and cannot be installed."
        exit 1
    fi
else
    echo "The ssh server is already installed."
fi

# 检查是否指定了 --allow-root-passwd
if [ "$(has_param "-p" "--allow-root-passwd")" == "true" ]; then
    # 检查当前用户是否为 root
    if [ "$(id -u)" -eq 0 ]; then
        allow_root_passwd=$(get_param_value "-p" "--allow-root-passwd" | tr '[:upper:]' '[:lower:]')
        
        sshd_config_file="/etc/ssh/sshd_config"
        new_sshd_permit_root_login_setting=""

        if [ "$allow_root_passwd" == "yes" ]; then
            new_sshd_permit_root_login_setting="PermitRootLogin yes"
            echo "Setting: Root user is allowed to log in with password."
        elif [ "$allow_root_passwd" == "no" ]; then
            new_sshd_permit_root_login_setting="PermitRootLogin prohibit-password"
            echo "Setting: Root user is prohibited from logging in with password."
        else
            echo "Please specify 'yes' or 'no' for --allow-root-passwd."
            exit 1
        fi

        if grep -qE '^#?PermitRootLogin' "$sshd_config_file"; then
            sed -i "s@^#?PermitRootLogin.*@$new_sshd_permit_root_login_setting@g" "$sshd_config_file"
        else
            echo "$new_sshd_permit_root_login_setting" >> "$sshd_config_file"
        fi
        echo "SSHD config updated. Please restart sshd service to apply changes."

    else
        echo "The script is executed as a non-root user and cannot set whether to allow root to log in with a password."
        exit 1
    fi
fi

# 更新密钥.
update_sshkeys

# 检查是否指定了 --cron
if [ "$(has_param "-c" "--cron")" == "true" ]; then
    # 检查 Crontab 是否已安装
    if [ "$(command -v crontab)" == "" ]; then
        if [ "$(id -u)" -eq 0 ]; then
            echo "The crontab is not installed, and the script is executed as a root user, so it will be installed."
            if [ -f /etc/redhat-release ]; then
                yum install -y crontabs
            elif [ -f /etc/debian_version ]; then
                apt-get update
                apt-get install -y cron
            fi
            echo "The crontab has been installed."
        else
            echo "The crontab is not installed, but the script is executed as a non-root user and cannot be installed."
            exit 1
        fi
    else
        echo "The crontab is already installed."
    fi
    cron=$(get_param_value "-c" "--cron" | tr '[:upper:]' '[:lower:]')
    if [ "$cron" == "false" ]; then
        # 检查 Crontab 是否已经设置
        if [ "$( (crontab -l 2>/dev/null || true) | grep -c "conf-sshd.sh" )" -eq 0 ]; then
            echo "Crontab already clean. Will not be configured."
            exit 0
        else
            (crontab -l 2>/dev/null || true) | grep -v "conf-sshd.sh" | crontab -
            echo "Crontab has been removed."
            exit 0
        fi
    else
        if [ "$cron" == "" ]; then
            cron=$default_cron
        fi
        # 将当前脚本移动到 ~/.conf-sshd/conf-sshd.sh 中.
        mkdir -p ~/.conf-sshd
        # 检查当前脚本是否为文件
        if [ ! -f "$0" ]; then
            echo "Downloading conf-sshd script..."
            curl -oL ~/.conf-sshd/conf-sshd.sh "$script_url"
        else 
            echo "Copying conf-sshd script..."
            cp "$0" ~/.conf-sshd/conf-sshd.sh
        fi
        chmod +x ~/.conf-sshd/conf-sshd.sh
        echo "Install conf-sshd script successfully."
        # 将当前脚本追加到当前用户的 Crontab 中
        echo "Configuring Crontab..."
        cron_command="\"/bin/bash ~/.conf-sshd/conf-sshd.sh -o\" >> ~/.conf-sshd/run.log 2>&1"
        cron_job="$cron $cron_command"

        (crontab -l 2>/dev/null || true | grep -v "conf-sshd.sh") | { cat; echo "$cron_job"; } | crontab -

        echo "Crontab has been configured.(Cron: '$cron')"
    fi
fi
