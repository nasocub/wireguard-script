#!/usr/bin/env bash

#
# 通用 VPN 智能路由管理脚本 (合并版)
# 版本: 2.3 (修改以支持仅出站代理，不影响入站)
#
# 更新日志:
# v2.3: 优化策略路由，确保 VPN 仅代理服务器的出站流量，不影响 IPv4/IPv6 入站服务。
#       移除可能导致入站问题的全局路由规则，采用更精细的 `ip rule` 策略。
#       为 WireGuard 和 OpenVPN 统一实现“仅代理出站”逻辑。
# v2.2: 修复当VPS有IPv6而OpenVPN无IPv6时，出站IPv6流量被阻断的问题。
#       现在会自动将IPv6流量封装在IPv4 VPN隧道中发出。
# v2.1: 改进状态检查，使用 ifconfig.co 显示更详细的出站 IP 和服务商信息。
# v2.0: 合并 WireGuard 和 OpenVPN 脚本，提供统一管理菜单。
#
# 功能:
# 1. 统一管理 WireGuard 和 OpenVPN 客户端。
# 2. 允许用户选择使用 WireGuard 或 OpenVPN 作为出站代理。
# 3. 智能配置策略路由，仅将服务器的出站流量通过VPN发送，不影响入站服务。
# 4. 完整保留各协议原有的IPv6处理逻辑，并修复特殊场景下的连接问题。
# 5. 提供菜单式管理界面，易于操作。
#

# --- 全局变量和通用函数 ---
export DEBIAN_FRONTEND=noninteractive

# --- OpenVPN 专用全局变量 ---
OVPN_CONFIG_DIR="/etc/openvpn/client"
OVPN_CONFIG_NAME="client.conf"
OVPN_AUTH_FILE="/etc/openvpn/auth.txt"
OVPN_UP_SCRIPT="/etc/openvpn/up.sh"
OVPN_DOWN_SCRIPT="/etc/openvpn/down.sh"
LOG_FILE="/var/log/openvpn_smart_route.log"

# --- 字体颜色 ---
warning() { echo -e "\033[31m\033[01m$*\033[0m"; } # 红色
error() { echo -e "\033[31m\033[01m$*\033[0m" && exit 1; } # 红色并退出
info() { echo -e "\033[32m\033[01m$*\033[0m"; }  # 绿色
hint() { echo -e "\033[33m\033[01m$*\033[0m"; }  # 黄色
reading() { read -rp "$(info "$1")" "$2"; }

# --- 通用核心功能函数 ---

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

# 合并后的依赖检查
check_dependencies() {
    hint "正在检查并安装必要的依赖..."
    DEPS_CHECK=("ping" "wget" "curl" "ip" "openvpn" "wg-quick")
    DEPS_INSTALL=("iputils-ping" "wget" "curl" "iproute2" "openvpn" "wireguard-tools")
    
    if [ "$SYSTEM" = "Debian" ] || [ "$SYSTEM" = "Ubuntu" ]; then
        DEPS_CHECK+=("resolvconf")
        DEPS_INSTALL+=("resolvconf")
    fi
    
    DEPS_TO_INSTALL=()

    for i in "${!DEPS_CHECK[@]}"; do
        if ! type -p "${DEPS_CHECK[i]}" > /dev/null; then
             DEPS_TO_INSTALL+=(${DEPS_INSTALL[i]})
        fi
    done

    DEPS_TO_INSTALL=($(printf "%s\n" "${DEPS_TO_INSTALL[@]}" | sort -u | tr '\n' ' '))

    if [ "${#DEPS_TO_INSTALL[@]}" -ge 1 ];
    then
        info "需要安装的依赖: ${DEPS_TO_INSTALL[@]}"
        ${PACKAGE_UPDATE[int]} >/dev/null 2>&1
        ${PACKAGE_INSTALL[int]} ${DEPS_TO_INSTALL[@]} >/dev/null 2>&1
    else
        info "所有基本依赖已满足。"
    fi
    
    # 分别确认安装结果
    if ! type -p openvpn > /dev/null; then
        warning "警告：OpenVPN 安装失败，相关功能可能无法使用。"
    fi
    if ! type -p wg-quick > /dev/null; then
        warning "警告：wireguard-tools 安装失败，相关功能可能无法使用。"
    fi
}

# 通用的启用IPv6功能
enable_ipv6() {
    if [ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ]; then
        if [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" -eq 1 ]; then
            info "检测到系统已禁用IPv6，正在为您启用..."
            sed -i '/net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.conf
            sed -i '/net.ipv6.conf.default.disable_ipv6/d' /etc/sysctl.conf
            sed -i '/net.ipv6.conf.lo.disable_ipv6/d' /etc/sysctl.conf
            echo "net.ipv6.conf.all.disable_ipv6 = 0" >> /etc/sysctl.conf
            echo "net.ipv6.conf.default.disable_ipv6 = 0" >> /etc/sysctl.conf
            echo "net.ipv6.conf.lo.disable_ipv6 = 0" >> /etc/sysctl.conf
            sysctl -p >/dev/null 2>&1
            info "系统级IPv6已启用。"
        fi
    fi
}

# --- WireGuard 功能函数 (wg_前缀) ---

wg_manual_input_config() {
    hint "\n--- 请输入您的 WireGuard [Interface] 配置 ---\n"
    reading "接口私钥 (PrivateKey): " WG_PRIVATE_KEY
    reading "接口地址 (Address, 多个用逗号隔开 e.g., 10.0.0.2/24,fd00::2/64): " WG_ADDRESS
    reading "接口DNS (可选, 默认 1.1.1.1,8.8.8.8): " WG_DNS
    WG_DNS=${WG_DNS:-"1.1.1.1,8.8.8.8"}

    hint "\n--- 请输入您的 WireGuard [Peer] 配置 ---\n"
    reading "Peer公钥 (PublicKey): " PEER_PUBLIC_KEY
    reading "Peer预共享密钥 (PresharedKey, 可选): " PEER_PRESHARED_KEY
    reading "Peer端点 (Endpoint, e.g., your.server.com:51820): " PEER_ENDPOINT
    # PEER_ALLOWED_IPS will be managed by policy routing, but we still need a value for wg0.conf.
    # For outbound-only, it's safer to set it to the peer's internal IP.
    # However, if the user provides 0.0.0.0/0, we respect it but manage routing via PostUp/Down.
    reading "Peer允许的IP (AllowedIPs, 默认 0.0.0.0/0,::/0): " PEER_ALLOWED_IPS
    PEER_ALLOWED_IPS=${PEER_ALLOWED_IPS:-"0.0.0.0/0,::/0"}
    reading "持久连接 (PersistentKeepalive, 可选, 建议 25): " PEER_KEEPALIVE

    [ -z "$WG_PRIVATE_KEY" ] && error "错误：接口私钥(PrivateKey)不能为空。"
    [ -z "$WG_ADDRESS" ] && error "错误：接口地址(Address)不能为空。"
    [ -z "$PEER_PUBLIC_KEY" ] && error "错误：Peer公钥(PublicKey)不能为空。"
    [ -z "$PEER_ENDPOINT" ] && error "错误：Peer端点(Endpoint)不能为空。"
}

wg_set_ipv6_takeover_policy() {
    WG_IPV6_TAKEOVER="n"
    LAN6=$(ip -6 route get 2001:4860:4860::8888 2>/dev/null | awk '{print $10}' | head -n1)
    if [ -n "$LAN6" ]; then
        hint "\n--- WireGuard IPv6 出口策略 ---"
        echo "检测到您的服务器拥有原生IPv6地址 ($LAN6)。"
        hint "是否让 WireGuard 完全接管所有 IPv6 出站流量？"
        echo " - 选择 'y'，所有IPv6流量将通过WireGuard出口。"
        echo " - 选择 'n'，脚本将保留原生IPv6地址作为出口。"
        reading "让 WireGuard 接管原生 IPv6 出口吗？[y/N]: " takeover_choice
        if [[ "${takeover_choice,,}" == "y" ]]; then
            WG_IPV6_TAKEOVER="y"
        fi
    fi
}

wg_install() {
    # 冲突检测
    if systemctl is-active --quiet "openvpn-client@${OVPN_CONFIG_NAME%.*}"; then
        warning "警告：检测到 OpenVPN 客户端正在运行。同时运行两种VPN可能会导致网络问题。"
        reading "是否继续安装 WireGuard？[y/N]: " confirm_install
        if [[ "${confirm_install,,}" != "y" ]]; then
            info "操作已取消。"
            return
        fi
    fi
    
    if [ -f /etc/wireguard/wg0.conf ]; then
        warning "检测到已存在的 wg0.conf 配置文件。将先为您执行清理..."
        wg_uninstall "no-prompt"
        info "清理完成，现在开始新的安装。"
    fi

    info "正在生成 WireGuard 配置文件..."
    wg_manual_input_config

    if [[ "$WG_ADDRESS" == *":"* ]] || [[ "$PEER_ALLOWED_IPS" == *":"* ]]; then
        enable_ipv6
    fi
    
    LAN4=$(ip -4 route get 8.8.8.8 2>/dev/null | awk '{print $7}' | head -n1)
    LAN6=$(ip -6 route get 2001:4860:4860::8888 2>/dev/null | awk '{print $10}' | head -n1)
    wg_set_ipv6_takeover_policy
    
    mkdir -p /etc/wireguard
    
    # Define TABLE_ID for policy routing
    local TABLE_ID=100

    # Start building PostUp and PostDown rules
    # We will clear existing rules for this table/priority before adding new ones
    POSTUP_RULES="ip rule del table ${TABLE_ID} suppress_prefixlength 0 priority 100 2>/dev/null; "
    POSTUP_RULES+="ip -6 rule del table ${TABLE_ID} suppress_prefixlength 0 priority 100 2>/dev/null; "
    POSTUP_RULES+="ip rule del ipproto tcp dport 22 table main priority 50 2>/dev/null; " # Clean up SSH rule
    POSTUP_RULES+="ip route flush table ${TABLE_ID} 2>/dev/null; " # Clear routes in the custom table

    POSTDOWN_RULES="ip rule del table ${TABLE_ID} suppress_prefixlength 0 priority 100 2>/dev/null; "
    POSTDOWN_RULES+="ip -6 rule del table ${TABLE_ID} suppress_prefixlength 0 priority 100 2>/dev/null; "
    POSTDOWN_RULES+="ip rule del ipproto tcp dport 22 table main priority 50 2>/dev/null; " # Clean up SSH rule
    POSTDOWN_RULES+="ip route flush table ${TABLE_ID} 2>/dev/null; " # Clear routes in the custom table

    # Add interface addresses
    IFS=',' read -ra ADDRS <<< "$WG_ADDRESS"
    for addr in "${ADDRS[@]}"; do
        addr=$(echo "$addr" | xargs)
        [ -n "$addr" ] && POSTUP_RULES+="ip address add $addr dev %i; " && POSTDOWN_RULES+="ip address del $addr dev %i; "
    done

    # Add default routes to the VPN table (TABLE_ID) via the WireGuard interface
    # This ensures all traffic using TABLE_ID goes through the VPN interface.
    POSTUP_RULES+="ip route add default dev %i table ${TABLE_ID}; "
    POSTUP_RULES+="ip -6 route add default dev %i table ${TABLE_ID}; "

    # Add rules to direct *outbound* traffic originating from the server's main IPs to the VPN table.
    # This ensures that traffic *from* the server goes out via VPN, but inbound is unaffected.
    # The `suppress_prefixlength 0` rule makes this table the preferred default for locally originated traffic.
    POSTUP_RULES+="ip rule add table ${TABLE_ID} suppress_prefixlength 0 priority 100; "

    if [ -n "$LAN6" ]; then
        if [ "$WG_IPV6_TAKEOVER" == "y" ]; then
            # If IPv6 takeover is 'y', then outbound IPv6 from LAN6 also goes via VPN table.
            POSTUP_RULES+="ip -6 rule add table ${TABLE_ID} suppress_prefixlength 0 priority 100; "
            info "已配置 WireGuard IPv6 接管原生出口。"
        else
            # If not taking over IPv6, then outbound IPv6 from LAN6 uses main table.
            # So, we do not add a rule for LAN6 to TABLE_ID.
            info "已配置保留原生 IPv6 出口。"
        fi
    fi

    # Add a rule to ensure SSH (port 22) traffic from the server uses the main table.
    # This is for outbound SSH connections initiated by the server, ensuring they bypass the VPN.
    # For inbound SSH, existing routes should handle it as we are not overriding the main default route.
    POSTUP_RULES+="ip rule add ipproto tcp dport 22 table main priority 50; "

    # Write the wg0.conf file
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = ${WG_PRIVATE_KEY}
DNS = ${WG_DNS}
PostUp = ${POSTUP_RULES}
PostDown = ${POSTDOWN_RULES}

[Peer]
PublicKey = ${PEER_PUBLIC_KEY}
Endpoint = ${PEER_ENDPOINT}
AllowedIPs = ${PEER_ALLOWED_IPS}
EOF

    [ -n "$PEER_PRESHARED_KEY" ] && echo "PresharedKey = ${PEER_PRESHARED_KEY}" >> /etc/wireguard/wg0.conf
    [ -n "$PEER_KEEPALIVE" ] && echo "PersistentKeepalive = ${PEER_KEEPALIVE}" >> /etc/wireguard/wg0.conf

    info "配置文件 /etc/wireguard/wg0.conf 已生成。"
    
    info "正在停止任何可能存在的 wg0 接口以确保环境干净..."
    systemctl stop wg-quick@wg0 >/dev/null 2>&1
    ip link delete wg0 2>/dev/null
    sleep 1

    systemctl enable wg-quick@wg0 >/dev/null 2>&1
    info "正在启动新的 wg0 接口..."
    systemctl start wg-quick@wg0

    sleep 3
    if systemctl is-active --quiet wg-quick@wg0; then
        info "WireGuard (wg0) 接口已成功启动！"
        wg_show_status
    else
        error "错误：WireGuard (wg0) 接口启动失败。请检查配置或使用 'journalctl -u wg-quick@wg0' 查看日志。"
    fi
}

wg_on_off() {
    if [ ! -f /etc/wireguard/wg0.conf ]; then
        error "错误：配置文件 /etc/wireguard/wg0.conf 不存在，请先安装。"
    fi
    
    if systemctl is-active --quiet wg-quick@wg0; then
        hint "正在关闭 WireGuard (wg0) 接口..."
        wg-quick down wg0
        info "接口已关闭。"
    else
        hint "正在启动 WireGuard (wg0) 接口..."
        wg-quick up wg0
        info "接口已启动。"
    fi
}

wg_uninstall() {
    local prompt=${1:-"prompt"}
    
    if [ "$prompt" = "prompt" ]; then
        hint "你确定要卸载 WireGuard 接口并删除配置文件吗？"
        reading "[y/N]: " confirm
        if [[ "${confirm,,}" != "y" ]]; then
            info "操作已取消。"
            return
        fi
    fi
    
    info "正在停止并禁用服务..."
    systemctl stop wg-quick@wg0 >/dev/null 2>&1
    systemctl disable wg-quick@wg0 >/dev/null 2>&1
    
    # Clean up policy routing rules manually as wg-quick down might not always remove them perfectly
    local TABLE_ID=100
    ip rule del table ${TABLE_ID} suppress_prefixlength 0 priority 100 2>/dev/null
    ip -6 rule del table ${TABLE_ID} suppress_prefixlength 0 priority 100 2>/dev/null
    ip rule del ipproto tcp dport 22 table main priority 50 2>/dev/null
    ip route flush table ${TABLE_ID} 2>/dev/null
    
    info "正在删除配置文件..."
    rm -f /etc/wireguard/wg0.conf
    
    if [ "$prompt" = "prompt" ]; then
        reading "是否要卸载 wireguard-tools 依赖包？[y/N]: " uninstall_deps
        if [[ "${uninstall_deps,,}" == "y" ]]; then
            info "正在卸载 wireguard-tools..."
            ${PACKAGE_UNINSTALL[int]} wireguard-tools >/dev/null 2>&1
        fi
        info "卸载完成。"
    fi
}

wg_show_status() {
    if ! systemctl is-active --quiet wg-quick@wg0; then
        warning "WireGuard (wg0) 接口当前未运行。"
        return
    fi
    
    info "\n--- WireGuard 状态 ---"
    wg show wg0
    
    hint "\n--- 网络连通性测试 ---"
    info "IPv4 出站信息:"
    if ! curl -4s --connect-timeout 10 ifconfig.co; then
        warning "无法获取 IPv4 出站信息 (无连接或超时)。"
    fi
    echo "----------------------------------------------"
    info "IPv6 出站信息:"
    if ! curl -6s --connect-timeout 10 ifconfig.co; then
        warning "无法获取 IPv6 出站信息 (无连接或超时)。"
    fi
    echo ""
}


# --- OpenVPN 功能函数 (open_前缀) ---

open_set_ipv6_takeover_policy() {
    OVPN_IPV6_TAKEOVER="n"
    LAN6=$(ip -6 route get 2001:4860:4860::8888 2>/dev/null | awk '{print $10}' | head -n1)
    if [ -n "$LAN6" ]; then
        hint "\n--- OpenVPN IPv6 出口策略 ---"
        echo "检测到您的服务器拥有原生IPv6地址 ($LAN6)。"
        hint "是否让 OpenVPN 完全接管所有 IPv6 出站流量？"
        hint "选择 'y'，所有IPv6流量将走VPN (如果VPN支持IPv6)。"
        hint "选择 'n' (默认)，服务器本身的IPv6流量将走原生网络。"
        reading "让 OpenVPN 接管原生 IPv6 出口吗？[y/N]: " takeover_choice
        if [[ "${takeover_choice,,}" == "y" ]]; then
            OVPN_IPV6_TAKEOVER="y"
        fi
    fi
}

open_install() {
    # 冲突检测
    if systemctl is-active --quiet wg-quick@wg0; then
        warning "警告：检测到 WireGuard 正在运行。同时运行两种VPN可能会导致网络问题。"
        reading "是否继续安装 OpenVPN？[y/N]: " confirm_install
        if [[ "${confirm_install,,}" != "y" ]]; then
            info "操作已取消。"
            return
        fi
    fi

    if [ -f "${OVPN_CONFIG_DIR}/${OVPN_CONFIG_NAME}" ]; then
        warning "检测到已存在的OpenVPN配置。将先为您执行清理..."
        open_uninstall "no-prompt"
        info "清理完成，现在开始新的安装。"
    fi
    
    mkdir -p "$OVPN_CONFIG_DIR"

    hint "--- OpenVPN 配置 ---"
    echo "请选择提供 .ovpn 配置的方式:"
    hint "1. 输入 .ovpn 文件的完整路径"
    hint "2. 直接粘贴 .ovpn 文件的内容"
    reading "请输入选项 [1-2]: " input_choice

    case "$input_choice" in
        1)
            reading "请输入您的 .ovpn 配置文件的完整路径: " ovpn_file_path
            [ ! -f "$ovpn_file_path" ] && error "错误：找不到文件: $ovpn_file_path"
            cp "$ovpn_file_path" "${OVPN_CONFIG_DIR}/${OVPN_CONFIG_NAME}"
            ;;
        2)
            hint "请粘贴您的 .ovpn 文件内容。粘贴完成后，在新的一行输入 'OVPN_END' (区分大小写) 并按回车键:"
            temp_ovpn_file=$(mktemp)
            while IFS= read -r line; do
                [[ "$line" == "OVPN_END" ]] && break
                echo "$line" >> "$temp_ovpn_file"
            done
            [ ! -s "$temp_ovpn_file" ] && rm "$temp_ovpn_file" && error "错误：没有粘贴任何内容。"
            mv "$temp_ovpn_file" "${OVPN_CONFIG_DIR}/${OVPN_CONFIG_NAME}"
            ;;
        *) error "无效选项。" ;;
    esac

    grep -qE "tun-ipv6|proto (udp6|tcp6)" "${OVPN_CONFIG_DIR}/${OVPN_CONFIG_NAME}" && enable_ipv6
    
    open_set_ipv6_takeover_policy

    # Remove existing redirect-gateway, dhcp-option DNS, and block-outside-dns
    # These are handled by the up/down scripts for policy routing.
    sed -i -e '/^redirect-gateway/d' -e '/^dhcp-option DNS/d' -e 's/^\s*block-outside-dns/#&/' "${OVPN_CONFIG_DIR}/${OVPN_CONFIG_NAME}"
    
    echo -e "\n# Added by script for policy routing" >> "${OVPN_CONFIG_DIR}/${OVPN_CONFIG_NAME}"
    echo "script-security 2" >> "${OVPN_CONFIG_DIR}/${OVPN_CONFIG_NAME}"
    echo "route-noexec" >> "${OVPN_CONFIG_DIR}/${OVPN_CONFIG_NAME}"
    echo "up $OVPN_UP_SCRIPT" >> "${OVPN_CONFIG_DIR}/${OVPN_CONFIG_NAME}"
    echo "down $OVPN_DOWN_SCRIPT" >> "${OVPN_CONFIG_DIR}/${OVPN_CONFIG_NAME}"

    if grep -q "auth-user-pass" "${OVPN_CONFIG_DIR}/${OVPN_CONFIG_NAME}"; then
        if ! grep -q "auth-user-pass .*$" "${OVPN_CONFIG_DIR}/${OVPN_CONFIG_NAME}"; then
            hint "\n检测到配置需要用户名和密码认证。"
            reading "请输入用户名 (留空则跳过): " ovpn_user
            read -sp "$(info "请输入密码 (密码隐藏，留空则跳过): ")" ovpn_pass
            echo
            if [[ -n "$ovpn_user" || -n "$ovpn_pass" ]]; then
                info "正在创建认证文件..."
                echo "$ovpn_user" > "$OVPN_AUTH_FILE"
                echo "$ovpn_pass" >> "$OVPN_AUTH_FILE"
                chmod 600 "$OVPN_AUTH_FILE"
                sed -i "s|^\s*auth-user-pass\s*$|auth-user-pass $OVPN_AUTH_FILE|" "${OVPN_CONFIG_DIR}/${OVPN_CONFIG_NAME}"
            else
                info "未提供认证信息，将不创建认证文件。"
            fi
        fi
    fi
    
    LAN4=$(ip -4 route get 8.8.8.8 2>/dev/null | awk '{print $7}' | head -n1)
    LAN6=$(ip -6 route get 2001:4860:4860::8888 2>/dev/null | awk '{print $10}' | head -n1) # Get LAN6 for policy decision

    # --- Start of UP script generation (MODIFIED for outbound-only) ---
    cat > "$OVPN_UP_SCRIPT" << EOF
#!/bin/bash
export PATH=\${PATH}:/usr/sbin
TABLE_ID=100
GW4=\${route_vpn_gateway}
GW6=\${ifconfig_ipv6_remote}

touch $LOG_FILE && chmod 644 $LOG_FILE
echo "\$(date): up.sh executing for device \$dev" >> $LOG_FILE

# Clear any previous rules for this table/priority before adding new ones
ip rule del table \$TABLE_ID suppress_prefixlength 0 priority 100 2>/dev/null
ip -6 rule del table \$TABLE_ID suppress_prefixlength 0 priority 100 2>/dev/null
ip rule del ipproto tcp dport 22 table main priority 50 2>/dev/null
ip route flush table \$TABLE_ID 2>/dev/null # Clear routes in the custom table

# --- IPv4 Routing ---
if [ -n "\$GW4" ]; then
    echo "\$(date): VPN IPv4 Gateway is \$GW4" >> $LOG_FILE
    # Add default route to the VPN table (TABLE_ID) via the VPN gateway
    ip route add default via \$GW4 dev \$dev table \$TABLE_ID
    # Add rule to direct *all* local outbound IPv4 traffic to the VPN table.
    # This ensures outbound traffic from the server goes via VPN, but inbound is unaffected.
    ip rule add table \$TABLE_ID suppress_prefixlength 0 priority 100
fi

# --- IPv6 Routing (MODIFIED LOGIC for outbound-only) ---
if [ -n "\$GW6" ]; then
    # Case 1: VPN provides a native IPv6 gateway.
    echo "\$(date): VPN IPv6 Gateway is \$GW6" >> $LOG_FILE
    ip -6 route add default via \$GW6 dev \$dev table \$TABLE_ID
    # Add rule to direct *all* local outbound IPv6 traffic to the VPN table.
    # This ensures outbound traffic from the server goes via VPN, but inbound is unaffected.
    ip -6 rule add table \$TABLE_ID suppress_prefixlength 0 priority 100
else
    # Case 2: VPN does NOT provide an IPv6 gateway.
    # Route all IPv6 egress via the VPN interface, to be encapsulated over IPv4.
    echo "\$(date): No VPN IPv6 Gateway. Routing all IPv6 egress via VPN interface \$dev (encapsulated)." >> $LOG_FILE
    ip -6 route add default dev \$dev table \$TABLE_ID
    # Add rule to direct *all* local outbound IPv6 traffic to the VPN table.
    ip -6 rule add table \$TABLE_ID suppress_prefixlength 0 priority 100
fi

# Add a rule to ensure SSH (port 22) traffic from the server uses the main table.
# This is for outbound SSH connections initiated by the server, ensuring they bypass the VPN.
# For inbound SSH, existing routes should handle it as we are not overriding the main default route.
ip rule add ipproto tcp dport 22 table main priority 50
EOF
    # --- End of UP script generation ---

    # --- Start of DOWN script generation (MODIFIED for outbound-only) ---
    cat > "$OVPN_DOWN_SCRIPT" << EOF
#!/bin/bash
export PATH=\${PATH}:/usr/sbin
TABLE_ID=100
echo "\$(date): down.sh executing for device \$dev. Cleaning up..." >> $LOG_FILE

# Cleanup IPv4 and IPv6 rules added by up.sh
ip rule del table \$TABLE_ID suppress_prefixlength 0 priority 100 2>/dev/null
ip -6 rule del table \$TABLE_ID suppress_prefixlength 0 priority 100 2>/dev/null
ip rule del ipproto tcp dport 22 table main priority 50 2>/dev/null
ip route flush table \$TABLE_ID 2>/dev/null

echo "\$(date): Cleanup complete." >> $LOG_FILE
EOF
    # --- End of DOWN script generation ---

    chmod +x "$OVPN_UP_SCRIPT" "$OVPN_DOWN_SCRIPT"
    
    info "\n配置完成。正在启动OpenVPN..."
    systemctl enable "openvpn-client@${OVPN_CONFIG_NAME%.*}" >/dev/null 2>&1
    systemctl restart "openvpn-client@${OVPN_CONFIG_NAME%.*}"

    sleep 5
    if systemctl is-active --quiet "openvpn-client@${OVPN_CONFIG_NAME%.*}"; then
        info "OpenVPN 客户端已成功启动！"
        open_show_status
    else
        error "错误：OpenVPN 客户端启动失败。请使用 'journalctl -u openvpn-client@${OVPN_CONFIG_NAME%.*}' 查看日志。"
    fi
}

open_on_off() {
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

open_uninstall() {
    local prompt=${1:-"prompt"}
    
    if [ "$prompt" = "prompt" ]; then
        hint "你确定要卸载 OpenVPN 客户端并删除所有相关配置吗？"
        reading "[y/N]: " confirm
        [[ "${confirm,,}" != "y" ]] && info "操作已取消。" && return
    fi
    
    info "正在停止并禁用服务..."
    systemctl stop "openvpn-client@${OVPN_CONFIG_NAME%.*}" >/dev/null 2>&1
    systemctl disable "openvpn-client@${OVPN_CONFIG_NAME%.*}" >/dev/null 2>&1
    
    # Clean up policy routing rules manually as down script might not always remove them perfectly
    local TABLE_ID=100
    ip rule del table ${TABLE_ID} suppress_prefixlength 0 priority 100 2>/dev/null
    ip -6 rule del table ${TABLE_ID} suppress_prefixlength 0 priority 100 2>/dev/null
    ip rule del ipproto tcp dport 22 table main priority 50 2>/dev/null
    ip route flush table ${TABLE_ID} 2>/dev/null

    info "正在删除配置文件和脚本..."
    rm -rf "$OVPN_CONFIG_DIR" "$OVPN_AUTH_FILE" "$OVPN_UP_SCRIPT" "$OVPN_DOWN_SCRIPT"
    rm -f "$LOG_FILE"
    
    if [ "$prompt" = "prompt" ]; then
        reading "是否要卸载 openvpn 软件包？[y/N]: " uninstall_deps
        if [[ "${uninstall_deps,,}" == "y" ]]; then
            info "正在卸载 openvpn..."
            ${PACKAGE_UNINSTALL[int]} openvpn >/dev/null 2>&1
        fi
        info "卸载完成。"
    fi
}

open_show_status() {
    if ! systemctl is-active --quiet "openvpn-client@${OVPN_CONFIG_NAME%.*}"; then
        warning "OpenVPN 客户端当前未运行。"
        return
    fi
    
    info "\n--- OpenVPN 状态 ---"
    systemctl status "openvpn-client@${OVPN_CONFIG_NAME%.*}" | grep "Active:"
    
    hint "\n--- 网络连通性测试 ---"
    info "IPv4 出站信息:"
    if ! curl -4s --connect-timeout 10 ifconfig.co; then
        warning "无法获取 IPv4 出站信息 (无连接或超时)。"
    fi
    echo "----------------------------------------------"
    info "IPv6 出站信息:"
    if ! curl -6s --connect-timeout 10 ifconfig.co; then
        warning "无法获取 IPv6 出站信息 (无连接或超时)。"
    fi
    echo ""
}

# --- 通用设置 ---

set_priority() {
    hint "\n--- 设置出站网络优先级 ---"
    echo "当访问双栈(IPv4/IPv6)网站时，系统将优先使用哪个协议？"
    hint "1. 优先使用 IPv4 (默认)"
    hint "2. 优先使用 IPv6"
    hint "0. 返回"
    reading "请输入选项 [0-2]: " priority_choice

    [ -f /etc/gai.conf ] && sed -i -e '/^precedence ::ffff:0:0\/96/d' -e '/^label 2002::\/16/d' /etc/gai.conf

    case "$priority_choice" in
        1) echo "precedence ::ffff:0:0/96  100" >> /etc/gai.conf; info "已设置优先使用 IPv4 出站。" ;;
        2) echo "label 2002::/16   2" >> /etc/gai.conf; info "已设置优先使用 IPv6 出站。" ;;
        0) return ;;
        *) warning "无效输入。" ;;
    esac
    sleep 2
}

# --- 菜单系统 ---

wg_menu() {
    clear
    echo "=============================================="
    echo "        WireGuard 智能路由管理"
    echo "=============================================="
    hint "1. 安装或重装一个新的 WireGuard 接口 (wg0)"
    hint "2. 启动 / 关闭 WireGuard 接口"
    hint "3. 查看 WireGuard 状态和网络"
    hint "4. 彻底卸载 WireGuard 接口"
    hint "0. 返回主菜单"
    echo "----------------------------------------------"
    reading "请输入选项 [0-4]: " choice

    case "$choice" in
        1) wg_install ;;
        2) wg_on_off ;;
        3) wg_show_status ;;
        4) wg_uninstall ;;
        0) return ;;\
        *) warning "无效输入。" && sleep 2 ;;
    esac
    [ "$choice" != "0" ] && wg_menu
}

open_menu() {
    clear
    echo "=============================================="
    echo "        OpenVPN 智能路由管理"
    echo "=============================================="
    hint "1. 安装并配置一个新的 OpenVPN 客户端"
    hint "2. 启动 / 关闭 OpenVPN 客户端"
    hint "3. 查看 OpenVPN 状态和网络"
    hint "4. 彻底卸载 OpenVPN"
    hint "0. 返回主菜单"
    echo "----------------------------------------------"
    reading "请输入选项 [0-4]: " choice

    case "$choice" in
        1) open_install ;;
        2) open_on_off ;;
        3) open_show_status ;;
        4) open_uninstall ;;
        0) return ;;\
        *) warning "无效输入。" && sleep 2 ;;
    esac
    [ "$choice" != "0" ] && open_menu
}

main_menu() {
    clear
    echo "=============================================="
    echo "      通用 VPN 智能路由管理脚本 v2.3"
    echo "=============================================="
    info "当前活动服务:"
    if systemctl is-active --quiet wg-quick@wg0; then
        info "  - WireGuard (wg0)   [运行中]"
    fi
    if systemctl is-active --quiet "openvpn-client@${OVPN_CONFIG_NAME%.*}"; then
        info "  - OpenVPN (client)  [运行中]"
    fi
    echo "----------------------------------------------"
    hint "1. 管理 WireGuard"
    hint "2. 管理 OpenVPN"
    hint "3. 通用设置 (出站优先级)"
    hint "0. 退出脚本"
    echo "=============================================="
    reading "请选择要执行的操作 [0-3]: " main_choice

    case "$main_choice" in
        1) wg_menu ;;
        2) open_menu ;;
        3) set_priority ;;
        0) exit 0 ;;
        *) warning "无效输入，请输入 0-3 之间的数字。" && sleep 2 ;;
    esac
}

# --- 脚本入口 ---
check_root
check_operating_system
check_dependencies

while true; do
    main_menu
done
