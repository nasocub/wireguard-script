#!/usr/bin/env bash

#
# 通用WireGuard管理脚本 (基于fscarmen/warp-sh修改)
# 版本: 1.5
# 更新日志:
# v1.5: 1.新增IPv6出口接管策略，允许WG的IPv6完全替代原生IPv6出口。2.增强接口清理机制，修复'wg0 already exists'错误。
# v1.4: 新增设置出站协议优先级(IPv4/IPv6)的功能。
# v1.3: 增加在安装时自动检测并启用系统级IPv6支持的功能。
# v1.2: 修复了在OpenVZ/LXC等容器化环境中IP地址分配失败的问题。
# v1.1: 修复了因缺少`resolvconf`依赖而启动失败的问题。
#
# 功能: 手动配置WireGuard接口，并智能配置策略路由，
#      实现仅出站流量走WireGuard，不影响入站服务。
#

# --- 全局变量和函数 ---
export DEBIAN_FRONTEND=noninteractive

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
    DEPS_CHECK=("ping" "wget" "curl" "ip")
    DEPS_INSTALL=("iputils-ping" "wget" "curl" "iproute2")
    
    # 为Debian/Ubuntu系统添加resolvconf依赖检查
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

    # 移除可能存在的重复项
    DEPS_TO_INSTALL=($(printf "%s\n" "${DEPS_TO_INSTALL[@]}" | sort -u | tr '\n' ' '))

    if [ "${#DEPS_TO_INSTALL[@]}" -ge 1 ];
    then
        info "需要安装的依赖: ${DEPS_TO_INSTALL[@]}"
        ${PACKAGE_UPDATE[int]} >/dev/null 2>&1
        ${PACKAGE_INSTALL[int]} ${DEPS_TO_INSTALL[@]} >/dev/null 2>&1
    else
        info "所有基本依赖已满足。"
    fi
    
    # 检查并安装wireguard-tools
    if ! type -p wg-quick > /dev/null; then
        info "正在安装 wireguard-tools..."
        ${PACKAGE_INSTALL[int]} wireguard-tools >/dev/null 2>&1
        if ! type -p wg-quick > /dev/null; then
            error "错误：wireguard-tools 安装失败，请手动安装后重试。"
        fi
    else
        info "wireguard-tools 已安装。"
    fi
}

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

# 2. 获取用户输入的WireGuard配置
manual_input_config() {
    hint "\n--- 请输入您的 WireGuard [Interface] 配置 ---\n"
    reading "接口私钥 (PrivateKey): " WG_PRIVATE_KEY
    reading "接口地址 (Address, 多个用逗号隔开 e.g., 10.0.0.2/24,fd00::2/64): " WG_ADDRESS
    reading "接口DNS (可选, 默认 1.1.1.1,8.8.8.8): " WG_DNS
    WG_DNS=${WG_DNS:-"1.1.1.1,8.8.8.8"}

    hint "\n--- 请输入您的 WireGuard [Peer] 配置 ---\n"
    reading "Peer公钥 (PublicKey): " PEER_PUBLIC_KEY
    reading "Peer预共享密钥 (PresharedKey, 可选): " PEER_PRESHARED_KEY
    reading "Peer端点 (Endpoint, e.g., your.server.com:51820): " PEER_ENDPOINT
    reading "Peer允许的IP (AllowedIPs, 默认 0.0.0.0/0,::/0): " PEER_ALLOWED_IPS
    PEER_ALLOWED_IPS=${PEER_ALLOWED_IPS:-"0.0.0.0/0,::/0"}
    reading "持久连接 (PersistentKeepalive, 可选, 建议 25): " PEER_KEEPALIVE

    # 验证输入
    [ -z "$WG_PRIVATE_KEY" ] && error "错误：接口私钥(PrivateKey)不能为空。"
    [ -z "$WG_ADDRESS" ] && error "错误：接口地址(Address)不能为空。"
    [ -z "$PEER_PUBLIC_KEY" ] && error "错误：Peer公钥(PublicKey)不能为空。"
    [ -z "$PEER_ENDPOINT" ] && error "错误：Peer端点(Endpoint)不能为空。"
}

# [v1.5 新增] 设置IPv6接管策略
set_ipv6_takeover_policy() {
    WG_IPV6_TAKEOVER="n" # 默认为不接管
    if [ -n "$LAN6" ]; then
        hint "\n--- IPv6 出口策略 ---"
        echo "检测到您的服务器拥有原生IPv6地址 ($LAN6)。"
        hint "是否让 WireGuard 完全接管所有 IPv6 出站流量？"
        echo " - 选择 'y'，所有IPv6流量将通过WireGuard出口。这会使用WireGuard的IPv6地址访问网络。"
        echo " - 选择 'n'，脚本将保留原生IPv6地址作为出口。这适合需要从固定原生IP访问某些服务的场景。"
        reading "让 WireGuard 接管原生 IPv6 出口吗？[y/N]: " takeover_choice
        if [[ "${takeover_choice,,}" == "y" ]]; then
            WG_IPV6_TAKEOVER="y"
        fi
    fi
}


# 3. 生成配置文件并设置路由
install_wg() {
    # 如果已存在配置，先执行卸载流程进行清理
    if [ -f /etc/wireguard/wg0.conf ]; then
        warning "检测到已存在的 wg0.conf 配置文件。将先为您执行清理..."
        uninstall_wg "no-prompt"
        info "清理完成，现在开始新的安装。"
    fi

    info "正在生成 WireGuard 配置文件..."
    manual_input_config

    # 如果配置中包含IPv6地址，则确保系统启用IPv6
    if [[ "$WG_ADDRESS" == *":"* ]] || [[ "$PEER_ALLOWED_IPS" == *":"* ]]; then
        enable_ipv6
    fi
    
    # 获取服务器IP并询问IPv6接管策略
    LAN4=$(ip -4 route get 8.8.8.8 2>/dev/null | awk '{print $7}' | head -n1)
    LAN6=$(ip -6 route get 2001:4860:4860::8888 2>/dev/null | awk '{print $10}' | head -n1)
    set_ipv6_takeover_policy
    
    mkdir -p /etc/wireguard
    
    # 写入基础配置
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = ${WG_PRIVATE_KEY}
DNS = ${WG_DNS}
EOF

    # 写入路由策略 (核心部分)
    POSTUP_RULES=""
    POSTDOWN_RULES=""
    
    # 将IP地址分配移入PostUp，以兼容OpenVZ/LXC等环境
    IFS=',' read -ra ADDRS <<< "$WG_ADDRESS"
    for addr in "${ADDRS[@]}"; do
        addr=$(echo "$addr" | xargs)
        if [ -n "$addr" ]; then
            POSTUP_RULES+="ip address add $addr dev %i; "
            POSTDOWN_RULES+="ip address del $addr dev %i; "
        fi
    done

    # IPv4 策略路由，保留原生IPv4入口
    if [ -n "$LAN4" ]; then
        POSTUP_RULES+="ip -4 rule add from ${LAN4} table main; "
        POSTDOWN_RULES+="ip -4 rule del from ${LAN4} table main; "
    fi

    # [v1.5] 根据用户选择决定IPv6策略
    if [ -n "$LAN6" ]; then
        if [ "$WG_IPV6_TAKEOVER" != "y" ]; then
            POSTUP_RULES+="ip -6 rule add from ${LAN6} table main; "
            POSTDOWN_RULES+="ip -6 rule del from ${LAN6} table main; "
            info "已配置保留原生 IPv6 出口。"
        else
            info "已配置 WireGuard IPv6 接管原生出口。"
        fi
    fi

    # Docker 容器的流量也走主路由表
    POSTUP_RULES+="ip -4 rule add from 172.17.0.0/16 table main 2>/dev/null; "
    POSTDOWN_RULES+="ip -4 rule del from 172.17.0.0/16 table main 2>/dev/null; "

    # 写入PostUp和PostDown
    echo "PostUp = ${POSTUP_RULES}" >> /etc/wireguard/wg0.conf
    echo "PostDown = ${POSTDOWN_RULES}" >> /etc/wireguard/wg0.conf

    # 写入Peer配置
    cat >> /etc/wireguard/wg0.conf << EOF

[Peer]
PublicKey = ${PEER_PUBLIC_KEY}
Endpoint = ${PEER_ENDPOINT}
AllowedIPs = ${PEER_ALLOWED_IPS}
EOF

    if [ -n "$PEER_PRESHARED_KEY" ]; then
        echo "PresharedKey = ${PEER_PRESHARED_KEY}" >> /etc/wireguard/wg0.conf
    fi
    if [ -n "$PEER_KEEPALIVE" ]; then
        echo "PersistentKeepalive = ${PEER_KEEPALIVE}" >> /etc/wireguard/wg0.conf
    fi

    info "配置文件 /etc/wireguard/wg0.conf 已生成。"
    
    # [v1.5] 增强启动流程以提高稳定性
    info "正在停止任何可能存在的 wg0 接口以确保环境干净..."
    systemctl stop wg-quick@wg0 >/dev/null 2>&1
    # 强制删除可能卡住的接口
    ip link delete wg0 2>/dev/null
    sleep 1

    systemctl enable wg-quick@wg0 >/dev/null 2>&1
    info "正在启动新的 wg0 接口..."
    systemctl start wg-quick@wg0

    sleep 3
    if systemctl is-active --quiet wg-quick@wg0; then
        info "WireGuard (wg0) 接口已成功启动！"
        show_status
    else
        error "错误：WireGuard (wg0) 接口启动失败。请检查配置或使用 'journalctl -u wg-quick@wg0' 查看日志。"
    fi
}

# 4. 其他管理功能
on_off() {
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

set_priority() {
    hint "\n--- 设置出站网络优先级 ---"
    echo "当前系统在访问双栈(IPv4/IPv6)网站时，会优先使用哪个协议？"
    hint "1. 优先使用 IPv4 (默认)"
    hint "2. 优先使用 IPv6"
    hint "0. 返回主菜单"
    reading "请输入选项 [0-2]: " priority_choice

    # 先清除旧的配置
    if [ -f /etc/gai.conf ]; then
        sed -i '/^precedence ::ffff:0:0\/96/d' /etc/gai.conf
        sed -i '/^label 2002::\/16/d' /etc/gai.conf
    fi

    case "$priority_choice" in
        1)
            echo "precedence ::ffff:0:0/96  100" >> /etc/gai.conf
            info "已设置优先使用 IPv4 出站。"
            ;;
        2)
            echo "label 2002::/16   2" >> /etc/gai.conf
            info "已设置优先使用 IPv6 出站。"
            ;;
        0)
            return
            ;;
        *)
            warning "无效输入。"
            ;;
    esac
    sleep 2
}

uninstall_wg() {
    local prompt=${1:-"prompt"} # 接收一个可选参数来跳过确认提示
    
    if [ "$prompt" = "prompt" ]; then
        hint "你确定要卸载 WireGuard 接口并删除配置文件吗？"
        reading "[y/N]: " confirm
        if [[ "${confirm,,}" != "y" ]]; then
            info "操作已取消。"
            exit 0
        fi
    fi
    
    info "正在停止并禁用服务..."
    systemctl stop wg-quick@wg0 >/dev/null 2>&1
    systemctl disable wg-quick@wg0 >/dev/null 2>&1
    
    info "正在删除配置文件..."
    rm -f /etc/wireguard/wg0.conf
    
    if [ "$prompt" = "prompt" ]; then
        # 询问是否卸载wireguard-tools
        reading "是否要卸载 wireguard-tools 依赖包？[y/N]: " uninstall_deps
        if [[ "${uninstall_deps,,}" == "y" ]]; then
            info "正在卸载 wireguard-tools..."
            ${PACKAGE_UNINSTALL[int]} wireguard-tools >/dev/null 2>&1
        fi
        info "卸载完成。"
    fi
}

show_status() {
    if ! systemctl is-active --quiet wg-quick@wg0; then
        warning "WireGuard (wg0) 接口当前未运行。"
        return
    fi
    
    info "\n--- WireGuard 状态 ---"
    wg show wg0
    
    hint "\n--- 网络连通性测试 ---"
    # 使用ip.sb进行测试，因为它同时支持v4和v6
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
    echo "      通用 WireGuard 智能路由管理脚本 v1.5"
    echo "=============================================="
    hint "1. 安装或重装一个新的 WireGuard 接口 (wg0)"
    hint "2. 启动 / 关闭 WireGuard 接口"
    hint "3. 查看 WireGuard 状态和网络"
    hint "4. 设置出站优先级 (IPv4/IPv6)"
    hint "5. 彻底卸载 WireGuard 接口"
    hint "0. 退出脚本"
    echo "----------------------------------------------"
    reading "请输入选项 [0-5]: " choice

    case "$choice" in
        1) install_wg ;;
        2) on_off ;;
        3) show_status ;;
        4) set_priority ;;
        5) uninstall_wg ;;
        0) exit 0 ;;
        *) warning "无效输入，请输入 0-5 之间的数字。" && sleep 2 ;;
    esac
}

# --- 脚本入口 ---
check_root
check_operating_system
check_dependencies

while true; do
    main_menu
done
