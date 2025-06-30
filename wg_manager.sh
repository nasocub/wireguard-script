#!/usr/bin/env bash

#
# 通用OpenVPN智能路由管理脚本
# 版本: 1.4
#
# 更新日志:
# v1.4: 修复策略路由问题。添加新规则确保从服务器本地发起的流量（如curl）正确通过VPN，同时保持入站连接的回复流量使用原生网关。
# v1.3: 改进认证处理。当提示输入用户名/密码时，若用户留空，则不创建认证文件直接尝试启动。
# v1.2: 自动注释掉.ovpn文件中不兼容的'block-outside-dns'指令，修复启动失败问题。
# v1.1: 新增安装时直接粘贴.ovpn内容的功能，无需预先上传文件。
#
# 功能:
# 1. 支持通过文件路径或直接粘贴内容来使用标准的.ovpn配置文件。
# 2. 通过策略路由，仅将服务器出站流量通过OpenVPN发送，不影响入站服务。
# 3. 支持在双栈服务器上，选择是否让OpenVPN完全接管IPv6出口。
# 4. 自动处理需要用户名/密码认证的配置文件。
# 5. 提供菜单式管理界面。
#

# --- 全局变量和函数 ---
export DEBIAN_FRONTEND=noninteractive
OVPN_CONFIG_DIR="/etc/openvpn/client"
OVPN_CONFIG_NAME="client.conf"
OVPN_AUTH_FILE="/etc/openvpn/auth.txt"
OVPN_UP_SCRIPT="/etc/openvpn/up.sh"
OVPN_DOWN_SCRIPT="/etc/openvpn/down.sh"

# 字体颜色
warning() { echo -e "\033[31m\033[01m$*\033[0m"; } # 红色
error() { echo -e "\033[31m\033[01m$*\033[0m" && exit 1; } # 红色并退出
info() { echo -e "\033[32m\033[01m$*\033[0m"; }  # 绿色
hint() { echo -e "\033[33m\033[01m$*\033[0m"; }  # 黄色
reading() { read -rp "$(info "$1")" "$2"; }

# --- 核心功能函数 ---

# 1. 检查环境和依赖
check_root() {
    [ "$(id -u)" != 0 ] && error "错误：必须以root用户身份运行此脚本。请尝试使用 'sudo -i'。"
}

check_operating_system() {
    if [ -s /etc/os-release ]; then
        SYS="$(grep -i pretty_name /etc/os-release | cut -d \" -f2)"
    elif [ -x "$(type -p hostnamectl)" ]; then
        SYS="$(hostnamectl | grep -i system | cut -d : -f2)"
    else
        SYS="未知系统"
    fi

    REGEX=("debian" "ubuntu" "centos|red hat|kernel|alma|rocky" "fedora")
    RELEASE=("Debian" "Ubuntu" "CentOS" "Fedora")
    PACKAGE_UPDATE=("apt-get -y update" "apt-get -y update" "yum -y update --skip-broken" "dnf -y update")
    PACKAGE_INSTALL=("apt-get -y install" "apt-get -y install" "yum -y install" "dnf -y install")
    PACKAGE_UNINSTALL=("apt-get -y autoremove" "apt-get -y autoremove" "yum -y autoremove" "dnf -y autoremove")

    for int in "${!REGEX[@]}"; do
        [[ "${SYS,,}" =~ ${REGEX[int]} ]] && SYSTEM="${RELEASE[int]}" && break
    done

    [ -z "$SYSTEM" ] && error "错误：此脚本仅支持 Debian, Ubuntu, CentOS, Fedora 系统。"
    info "检测到操作系统: $SYS"
}

check_dependencies() {
    hint "正在检查并安装必要的依赖..."
    DEPS_CHECK=("ping" "curl" "ip" "openvpn")
    DEPS_INSTALL=("iputils-ping" "curl" "iproute2" "openvpn")
    DEPS_TO_INSTALL=()

    for i in "${!DEPS_CHECK[@]}"; do
        if ! type -p "${DEPS_CHECK[i]}" > /dev/null; then
             DEPS_TO_INSTALL+=(${DEPS_INSTALL[i]})
        fi
    done

    if [ "${#DEPS_TO_INSTALL[@]}" -ge 1 ];
    then
        info "需要安装的依赖: ${DEPS_TO_INSTALL[@]}"
        ${PACKAGE_UPDATE[int]} >/dev/null 2>&1
        ${PACKAGE_INSTALL[int]} ${DEPS_TO_INSTALL[@]} >/dev/null 2>&1
    else
        info "所有基本依赖已满足。"
    fi
    
    if ! type -p openvpn > /dev/null; then
        error "错误：OpenVPN 安装失败，请手动安装后重试。"
    fi
}

enable_ipv6() {
    if [ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ] && [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" -eq 1 ]; then
        info "检测到系统已禁用IPv6，正在为您启用..."
        sysctl -w net.ipv6.conf.all.disable_ipv6=0
        sysctl -w net.ipv6.conf.default.disable_ipv6=0
        info "系统级IPv6已临时启用。为保证重启后生效，请手动修改 /etc/sysctl.conf 文件。"
    fi
}

set_ipv6_takeover_policy() {
    OVPN_IPV6_TAKEOVER="n" # 默认为不接管
    LAN6=$(ip -6 route get 2001:4860:4860::8888 2>/dev/null | awk '{print $10}' | head -n1)
    if [ -n "$LAN6" ]; then
        hint "\n--- IPv6 出口策略 ---"
        echo "检测到您的服务器拥有原生IPv6地址 ($LAN6)。"
        hint "是否让 OpenVPN 完全接管所有 IPv6 出站流量？"
        reading "让 OpenVPN 接管原生 IPv6 出口吗？[y/N]: " takeover_choice
        if [[ "${takeover_choice,,}" == "y" ]]; then
            OVPN_IPV6_TAKEOVER="y"
        fi
    fi
}

# 2. 安装和配置OpenVPN
install_ovpn() {
    if [ -f "${OVPN_CONFIG_DIR}/${OVPN_CONFIG_NAME}" ]; then
        warning "检测到已存在的OpenVPN配置。将先为您执行清理..."
        uninstall_ovpn "no-prompt"
        info "清理完成，现在开始新的安装。"
    fi
    
    mkdir -p "$OVPN_CONFIG_DIR"

    # 新增选择配置方式
    hint "--- OpenVPN 配置 ---"
    echo "请选择提供 .ovpn 配置的方式:"
    hint "1. 输入 .ovpn 文件的完整路径"
    hint "2. 直接粘贴 .ovpn 文件的内容"
    reading "请输入选项 [1-2]: " input_choice

    case "$input_choice" in
        1)
            reading "请输入您的 .ovpn 配置文件的完整路径 (e.g., /root/myconfig.ovpn): " ovpn_file_path
            if [ ! -f "$ovpn_file_path" ]; then
                error "错误：找不到指定的 .ovpn 文件: $ovpn_file_path"
            fi
            cp "$ovpn_file_path" "${OVPN_CONFIG_DIR}/${OVPN_CONFIG_NAME}"
            ;;
        2)
            hint "请粘贴您的 .ovpn 文件内容。粘贴完成后，在新的一行输入 'OVPN_END' (区分大小写) 并按回车键来结束:"
            temp_ovpn_file=$(mktemp)
            while IFS= read -r line; do
                if [[ "$line" == "OVPN_END" ]]; then
                    break
                fi
                echo "$line" >> "$temp_ovpn_file"
            done
            if [ ! -s "$temp_ovpn_file" ]; then
                rm "$temp_ovpn_file"
                error "错误：没有粘贴任何内容。"
            fi
            mv "$temp_ovpn_file" "${OVPN_CONFIG_DIR}/${OVPN_CONFIG_NAME}"
            ;;
        *)
            error "无效选项。"
            ;;
    esac

    # 检查是否需要IPv6支持
    if grep -qE "tun-ipv6|proto (udp6|tcp6)" "${OVPN_CONFIG_DIR}/${OVPN_CONFIG_NAME}"; then
        enable_ipv6
    fi
    
    set_ipv6_takeover_policy

    # 修改.ovpn配置文件以适应脚本
    # 移除与策略路由冲突的指令
    sed -i '/^redirect-gateway/d' "${OVPN_CONFIG_DIR}/${OVPN_CONFIG_NAME}"
    sed -i '/^dhcp-option DNS/d' "${OVPN_CONFIG_DIR}/${OVPN_CONFIG_NAME}"
    # [v1.2] 注释掉不兼容的 block-outside-dns 指令
    sed -i 's/^\s*block-outside-dns/#&/' "${OVPN_CONFIG_DIR}/${OVPN_CONFIG_NAME}"
    
    # 添加脚本钩子
    echo -e "\n# Added by script for policy routing" >> "${OVPN_CONFIG_DIR}/${OVPN_CONFIG_NAME}"
    echo "script-security 2" >> "${OVPN_CONFIG_DIR}/${OVPN_CONFIG_NAME}"
    echo "route-noexec" >> "${OVPN_CONFIG_DIR}/${OVPN_CONFIG_NAME}"
    echo "up $OVPN_UP_SCRIPT" >> "${OVPN_CONFIG_DIR}/${OVPN_CONFIG_NAME}"
    echo "down $OVPN_DOWN_SCRIPT" >> "${OVPN_CONFIG_DIR}/${OVPN_CONFIG_NAME}"

    # 处理用户认证
    if grep -q "auth-user-pass" "${OVPN_CONFIG_DIR}/${OVPN_CONFIG_NAME}"; then
        # 仅当没有指定认证文件时才提示输入
        if ! grep -q "auth-user-pass .*$" "${OVPN_CONFIG_DIR}/${OVPN_CONFIG_NAME}"; then
            hint "\n检测到您的配置可能需要用户名和密码认证。"
            hint "如果您的 .ovpn 文件内已包含认证信息 (如 cert/key)，请将此处留空。"
            reading "请输入用户名 (留空则跳过): " ovpn_user
            read -sp "$(info "请输入密码 (密码隐藏，留空则跳过): ")" ovpn_pass
            echo

            # 只有当用户输入了用户名或密码时才创建认证文件
            if [[ -n "$ovpn_user" || -n "$ovpn_pass" ]]; then
                info "已收到认证信息，正在创建认证文件..."
                echo "$ovpn_user" > "$OVPN_AUTH_FILE"
                echo "$ovpn_pass" >> "$OVPN_AUTH_FILE"
                chmod 600 "$OVPN_AUTH_FILE"
                # 修改配置文件以使用认证文件
                sed -i "s|^\s*auth-user-pass\s*$|auth-user-pass $OVPN_AUTH_FILE|" "${OVPN_CONFIG_DIR}/${OVPN_CONFIG_NAME}"
            else
                info "未提供用户名和密码，脚本将不创建认证文件。OpenVPN将按原配置启动。"
            fi
        fi
    fi
    
    # 创建up脚本
    LAN4=$(ip -4 route get 8.8.8.8 2>/dev/null | awk '{print $7}' | head -n1)
    
    cat > "$OVPN_UP_SCRIPT" << EOF
#!/bin/bash
export PATH=\${PATH}:/usr/sbin
# 路由表号
TABLE_ID=100
# 获取OpenVPN推送的网关
GW4=\${route_vpn_gateway}
GW6=\${ifconfig_ipv6_remote}

# IPv4策略路由
if [ -n "\$GW4" ]; then
    ip route add default via \$GW4 dev \$dev table \$TABLE_ID
    # [v1.4] 新增规则: 匹配从本地发出的流量(如curl)，使其走VPN路由表
    ip rule add iif lo table \$TABLE_ID priority 99
    # 保留规则: 匹配回复流量(源IP是本机IP)，使其走主路由表，保证入站连接正常
    ip rule add from $LAN4 table main priority 100
    # 确保SSH连接始终走原生网络以防失联
    ip rule add ipproto tcp dport 22 table main priority 101
    ip rule add not fwmark 0x2a table \$TABLE_ID priority 102
fi

# IPv6策略路由
if [ -n "\$GW6" ]; then
    ip -6 route add default via \$GW6 dev \$dev table \$TABLE_ID
    # [v1.4] 新增规则: 匹配从本地发出的流量(如curl)，使其走VPN路由表
    ip -6 rule add iif lo table \$TABLE_ID priority 99
    if [ "$OVPN_IPV6_TAKEOVER" != "y" ]; then
        # 保留规则: 匹配回复流量(源IP是本机IP)，使其走主路由表，保证入站连接正常
        ip -6 rule add from $LAN6 table main priority 100
    fi
    ip -6 rule add not fwmark 0x2a table \$TABLE_ID priority 102
fi
EOF

    # 创建down脚本
    cat > "$OVPN_DOWN_SCRIPT" << EOF
#!/bin/bash
export PATH=\${PATH}:/usr/sbin
TABLE_ID=100
# [v1.4] 清理iif lo规则
ip -4 rule del iif lo table \$TABLE_ID priority 99 2>/dev/null
ip -4 rule del from $LAN4 table main priority 100 2>/dev/null
ip -4 rule del ipproto tcp dport 22 table main priority 101 2>/dev/null
ip -4 rule del not fwmark 0x2a table \$TABLE_ID priority 102 2>/dev/null
# [v1.4] 清理iif lo规则
ip -6 rule del iif lo table \$TABLE_ID priority 99 2>/dev/null
if [ "$OVPN_IPV6_TAKEOVER" != "y" ]; then
    ip -6 rule del from $LAN6 table main priority 100 2>/dev/null
fi
ip -6 rule del not fwmark 0x2a table \$TABLE_ID priority 102 2>/dev/null
EOF

    chmod +x "$OVPN_UP_SCRIPT" "$OVPN_DOWN_SCRIPT"
    
    info "\n配置完成。正在启动OpenVPN..."
    systemctl enable "openvpn-client@${OVPN_CONFIG_NAME%.*}" >/dev/null 2>&1
    systemctl restart "openvpn-client@${OVPN_CONFIG_NAME%.*}"

    sleep 5
    if systemctl is-active --quiet "openvpn-client@${OVPN_CONFIG_NAME%.*}"; then
        info "OpenVPN 客户端已成功启动！"
        show_status
    else
        error "错误：OpenVPN 客户端启动失败。请使用 'journalctl -u openvpn-client@${OVPN_CONFIG_NAME%.*}' 查看日志。"
    fi
}

# 3. 其他管理功能
on_off() {
    if [ ! -f "${OVPN_CONFIG_DIR}/${OVPN_CONFIG_NAME}" ]; then
        error "错误：找不到OpenVPN配置文件，请先安装。"
    fi
    
    if systemctl is-active --quiet "openvpn-client@${OVPN_CONFIG_NAME%.*}"; then
        hint "正在关闭 OpenVPN 客户端..."
        systemctl stop "openvpn-client@${OVPN_CONFIG_NAME%.*}"
        info "客户端已关闭。"
    else
        hint "正在启动 OpenVPN 客户端..."
        systemctl start "openvpn-client@${OVPN_CONFIG_NAME%.*}"
        info "客户端已启动。"
    fi
}

uninstall_ovpn() {
    local prompt=${1:-"prompt"}
    
    if [ "$prompt" = "prompt" ]; then
        hint "你确定要卸载 OpenVPN 客户端并删除所有相关配置吗？"
        reading "[y/N]: " confirm
        if [[ "${confirm,,}" != "y" ]]; then
            info "操作已取消。"
            return
        fi
    fi
    
    info "正在停止并禁用服务..."
    systemctl stop "openvpn-client@${OVPN_CONFIG_NAME%.*}" >/dev/null 2>&1
    systemctl disable "openvpn-client@${OVPN_CONFIG_NAME%.*}" >/dev/null 2>&1
    
    info "正在删除配置文件和脚本..."
    rm -rf "$OVPN_CONFIG_DIR" "$OVPN_AUTH_FILE" "$OVPN_UP_SCRIPT" "$OVPN_DOWN_SCRIPT"
    
    if [ "$prompt" = "prompt" ]; then
        reading "是否要卸载 openvpn 软件包？[y/N]: " uninstall_deps
        if [[ "${uninstall_deps,,}" == "y" ]]; then
            info "正在卸载 openvpn..."
            ${PACKAGE_UNINSTALL[int]} openvpn >/dev/null 2>&1
        fi
        info "卸载完成。"
    fi
}

show_status() {
    if ! systemctl is-active --quiet "openvpn-client@${OVPN_CONFIG_NAME%.*}"; then
        warning "OpenVPN 客户端当前未运行。"
        return
    fi
    
    info "\n--- OpenVPN 状态 ---"
    systemctl status "openvpn-client@${OVPN_CONFIG_NAME%.*}" | grep "Active:"
    
    hint "\n--- 网络连通性测试 ---"
    IPV4_IP=$(curl -s -4 --connect-timeout 5 https://api.ip.sb/ip)
    IPV6_IP=$(curl -s -6 --connect-timeout 5 https://api.ip.sb/ip)
    
    if [ -n "$IPV4_IP" ]; then
        info "IPv4 出站 IP: $IPV4_IP"
    else
        warning "IPv4 出站: 无法访问"
    fi
    
    if [ -n "$IPV6_IP" ]; then
        info "IPv6 出站 IP: $IPV6_IP"
    else
        warning "IPv6 出站: 无法访问"
    fi
    echo ""
}

# --- 主菜单和执行逻辑 ---
main_menu() {
    clear
    echo "=============================================="
    echo "      通用 OpenVPN 智能路由管理脚本 v1.4"
    echo "=============================================="
    hint "1. 安装并配置一个新的 OpenVPN 客户端"
    hint "2. 启动 / 关闭 OpenVPN 客户端"
    hint "3. 查看 OpenVPN 状态和网络"
    hint "4. 彻底卸载 OpenVPN"
    hint "0. 退出脚本"
    echo "----------------------------------------------"
    reading "请输入选项 [0-4]: " choice

    case "$choice" in
        1) install_ovpn ;;
        2) on_off ;;
        3) show_status ;;
        4) uninstall_ovpn ;;
        0) exit 0 ;;
        *) warning "无效输入，请输入 0-4 之间的数字。" && sleep 2 ;;
    esac
}

# --- 脚本入口 ---
check_root
check_operating_system
check_dependencies

while true; do
    main_menu
done
