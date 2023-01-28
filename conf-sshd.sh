#!/bin/bash

########## 一些配置 ##########

# 默认获取 SSH key 的地方，一般是 Github.
sshkey_url="https://q-ssh.lamgc.me/ssh.keys"
# 默认的 Cron 执行计划, 每天凌晨 0 点执行
default_cron="0 0 * * *"
# 脚本 Url
script_url="https://q-ssh.lamgc.me"

############ 脚本区 ##########

script_params=$*
has_param() {
    for param in $script_params; do
        for tParam in $@; do
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
    for param in $script_params; do
        if [ "$find" == "true" ]; then
            if [[ $param == -* ]]; then
                return
            fi
            echo $param
            return
        fi
        for tParam in $@; do
            if [ "$tParam" == "$param" ]; then
                find=true
                break
            fi
        done
    done
}

use_param_keys_url() {
    local new_sshkey_url=$(get_param_value "-k" "--sshkey-url")
    if [ "$new_sshkey_url" == "" ]; then
        echo "Please specify the URL of the SSH public key."
        exit 1
    fi
    sshkey_url=$new_sshkey_url
    echo "A new SSH keys URL has been specified: $sshkey_url"
}

# 检查并更新 SSH key 地址.
if [ $(has_param "-k" "--sshkey-url") == "true" ]; then
    use_param_keys_url
fi

# 帮助信息.
if [ $(has_param "-h" "--help") == "true" ]; then
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -h, --help                              Print this help message."
    echo ""
    echo "Available to any user: "
    echo "  -k, --sshkey-url                        The URL of the SSH public key."
    echo "  -c, --cron [cron | false]               Configure Crontab to automatically update ssh keys,"
    echo "                                          Cron expression can be specified, If false is specified, "
    echo "                                          Crontab settings will be deleted automatically."
    echo ""
    echo "  -o, --only-update-keys                  Only update SSH keys, do not configure ssh server."
    echo "  -u, --update-self                       Update this script to the latest version."
    echo ""
    echo "only available when the script is executed as root:"
    echo "  -n, --no-install-sshd                   Do not install SSH Server."
    echo "  -p, --allow-root-passwd <yes | no>      Allow Root to log in with a password."
    echo ""
    exit 0
fi

update_sshkeys() {
    if [ "$sshkey_url" == "" ]; then
        echo "Please specify the URL of the SSH public key."
        exit 1
    fi
    echo "Downloading SSH public key from '$sshkey_url'"
    mkdir -p ~/.ssh
    local ssh_keys=$(curl -s $sshkey_url)
    if [ $? -ne 0 ] || [ "$ssh_keys" == "" ]; then
        echo "Failed to download SSH public key at $(date '+%Y-%m-%d %H:%M:%S')"
        exit 1
    fi
    echo "-------------------- SSH Keys --------------------"
    echo "$ssh_keys"
    echo "--------------------------------------------------"
    echo $ssh_keys > ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys
    # 输出更新成功，需要附带时间日期
    echo "SSH public key updated successfully at $(date '+%Y-%m-%d %H:%M:%S')"
}

# 检查是否只更新密钥.
if [ $(has_param "-o" "--only-update-keys") == "true" ]; then
    update_sshkeys
    exit 0
fi

# 检查是否指定了 --update-self
if [ $(has_param "-u" "--update-self") == "true" ]; then
    echo "Updating conf-sshd script..."
    cp $0 ~/.conf-sshd/conf-sshd.sh.bak
    curl -s $script_url > $0 || cp ~/.conf-sshd/conf-sshd.sh.bak $0 && echo "Script update failed at $(date '+%Y-%m-%d %H:%M:%S')" && exit 1
    chmod +x ~/.conf-sshd/conf-sshd.sh
    echo "Script updated successfully at $(date '+%Y-%m-%d %H:%M:%S')"
    exit 0
fi

# 检查 /usr/sbin/sshd 是否存在，且 /usr/sbin/sshd 执行后退出代码为 0
/usr/sbin/sshd -T > /dev/null
if [ $? -ne 0 ] && [ $(has_param "-n" "--no-install-sshd") == "false" ]; then
    if [ $(id -u) -eq 0 ]; then
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
if [ $(has_param "-p" "--allow-root-passwd") == "true" ]; then
    # 检查当前用户是否为 root
    if [ $(id -u) -eq 0 ]; then
        # 获取参数值
        allow_root_passwd=$(get_param_value "-p" "--allow-root-passwd" | tr '[:upper:]' '[:lower:]')
        if [ "$allow_root_passwd" == "yes" ]; then
            # 设置允许 root 使用密码登录
            sed -i 's/^#?PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config
            echo "Root user is allowed to log in with password."
        elif [ "$allow_root_passwd" == "no" ]; then
            # 设置禁止 root 使用密码登录
            sed -i 's/^#?PermitRootLogin.*/PermitRootLogin prohibit-password/g' /etc/ssh/sshd_config
            echo "Root user is prohibited from logging in with password."
        else
            echo "Please specify whether to allow root to log in with a password."
            exit 1
        fi
    else
        echo "The script is executed as a non-root user and cannot set whether to allow root to log in with a password."
        exit 1
    fi
fi

# 更新密钥.
update_sshkeys

# 检查是否指定了 --cron
if [ $(has_param "-c" "--cron") == "true" ]; then
    # 检查 Crontab 是否已安装
    if [ "$(command -v crontab)" == "" ]; then
        if [ $(id -u) -eq 0 ]; then
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
        if [ "$(crontab -l | grep "conf-sshd.sh")" == "" ]; then
            echo "Crontab will not be configured."
            exit 0
        else
            crontab -l | grep -v "conf-sshd.sh" | crontab -
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
        if [ ! -f $0 ]; then
            echo "Downloading conf-sshd script..."
            curl -o ~/.conf-sshd/conf-sshd.sh $script_url
        else 
            echo "Copying conf-sshd script..."
            cp $0 ~/.conf-sshd/conf-sshd.sh
        fi
        chmod +x ~/.conf-sshd/conf-sshd.sh
        echo "Install conf-sshd script successfully."
        # 将当前脚本添加到 Crontab 中
        echo "$cron /bin/bash ~/.conf-sshd/conf-sshd.sh -o -k $sshkey_url" | crontab -
    fi
fi
