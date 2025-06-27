#!/usr/bin/env bash

#
# 通用WireGuard管理脚本 (基于fscarmen/warp-sh修改)
# 版本: 1.0
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
    DEPS_TO_INSTALL=()

    for i in "${!DEPS_CHECK[@]}"; do
        [ ! -x "$(type -p ${DEPS_CHECK[i]})" ] && DEPS_TO_INSTALL+=(${DEPS_INSTALL[i]})
    done

    if [ "${#DEPS_TO_INSTALL[@]}" -ge 1 ];
    then
        info "需要安装的依赖: ${DEPS_TO_INSTALL[@]}"
        ${PACKAGE_UPDATE[int]} >/dev/null 2>&1
        ${PACKAGE_INSTALL[int]} ${DEPS_TO_INSTALL[@]} >/dev/null 2>&1
    else
        info "所有基本依赖已满足。"
    fi
    
    # 检查并安装wireguard-tools
    if [ ! -x "$(type -p wg-quick)" ]; then
        info "正在安装 wireguard-tools..."
        case "$SYSTEM" in
            "Debian"|"Ubuntu")
                ${PACKAGE_INSTALL[int]} wireguard-tools openresolv
                ;;
            "CentOS"|"Fedora")
                [ "$SYSTEM" = "CentOS" ] && ${PACKAGE_INSTALL[int]} epel-release
                ${PACKAGE_INSTALL[int]} wireguard-tools
                ;;
        esac
        [ ! -x "$(type -p wg-quick)" ] && error "错误：wireguard-tools 安装失败，请手动安装后重试。"
    else
        info "wireguard-tools 已安装。"
    fi
}

# 2. 获取用户输入的WireGuard配置
manual_input_config() {
    hint "\n--- 请输入您的 WireGuard [Interface] 配置 ---\n"
    reading "接口私钥 (PrivateKey): " WG_PRIVATE_KEY
    reading "接口地址 (Address, e.g., 10.0.0.2/24,fd00::2/64): " WG_ADDRESS
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

# 3. 生成配置文件并设置路由
install_wg() {
    info "正在生成 WireGuard 配置文件..."
    manual_input_config

    # 获取服务器主网卡IP
    LAN4=$(ip -4 route get 8.8.8.8 | awk '{print $7}' | head -n1)
    LAN6=$(ip -6 route get 2001:4860:4860::8888 | awk '{print $10}' | head -n1)
    
    mkdir -p /etc/wireguard
    
    # 写入基础配置
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = ${WG_PRIVATE_KEY}
Address = ${WG_ADDRESS}
DNS = ${WG_DNS}
EOF

    # 写入路由策略 (核心部分)
    # 这部分确保只有服务器主动发出的流量走wg0，而外部访问服务器的流量不受影响
    POSTUP_RULES=""
    POSTDOWN_RULES=""

    if [ -n "$LAN4" ]; then
        POSTUP_RULES+="ip -4 rule add from ${LAN4} table main; "
        POSTDOWN_RULES+="ip -4 rule del from ${LAN4} table main; "
    fi
    if [ -n "$LAN6" ]; then
        POSTUP_RULES+="ip -6 rule add from ${LAN6} table main; "
        POSTDOWN_RULES+="ip -6 rule del from ${LAN6} table main; "
    fi

    # Docker 容器的流量也走主路由表，防止影响容器网络
    POSTUP_RULES+="ip -4 rule add from 172.17.0.0/16 table main; "
    POSTDOWN_RULES+="ip -4 rule del from 172.17.0.0/16 table main; "

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
    
    # 启用并启动服务
    systemctl enable wg-quick@wg0 >/dev/null 2>&1
    systemctl restart wg-quick@wg0

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

uninstall_wg() {
    hint "你确定要卸载 WireGuard 接口并删除配置文件吗？"
    reading "[y/N]: " confirm
    if [[ "${confirm,,}" != "y" ]]; then
        info "操作已取消。"
        exit 0
    fi
    
    info "正在停止并禁用服务..."
    systemctl stop wg-quick@wg0 >/dev/null 2>&1
    systemctl disable wg-quick@wg0 >/dev/null 2>&1
    
    info "正在删除配置文件..."
    rm -f /etc/wireguard/wg0.conf
    
    # 询问是否卸载wireguard-tools
    reading "是否要卸载 wireguard-tools 依赖包？[y/N]: " uninstall_deps
    if [[ "${uninstall_deps,,}" == "y" ]]; then
        info "正在卸载 wireguard-tools..."
        ${PACKAGE_UNINSTALL[int]} wireguard-tools >/dev/null 2>&1
    fi

    info "卸载完成。"
}

show_status() {
    if ! systemctl is-active --quiet wg-quick@wg0; then
        warning "WireGuard (wg0) 接口当前未运行。"
        return
    fi
    
    info "\n--- WireGuard 状态 ---"
    wg show wg0
    
    hint "\n--- 网络连通性测试 ---"
    IPV4_CHECK=$(curl -s -4 --connect-timeout 5 https://www.cloudflare.com/cdn-cgi/trace | grep 'warp=' | sed 's/warp=//')
    IPV6_CHECK=$(curl -s -6 --connect-timeout 5 https://www.cloudflare.com/cdn-cgi/trace | grep 'warp=' | sed 's/warp=//')
    
    if [ -n "$IPV4_CHECK" ]; then
        info "IPv4 出站: 正在通过 WireGuard ($IPV4_CHECK)"
        info "IPv4 IP: $(curl -s -4 https://ip.sb)"
    else
        warning "IPv4 出站: 未通过 WireGuard"
    fi
    
    if [ -n "$IPV6_CHECK" ]; then
        info "IPv6 出站: 正在通过 WireGuard ($IPV6_CHECK)"
        info "IPv6 IP: $(curl -s -6 https://ip.sb)"
    else
        warning "IPv6 出站: 未通过 WireGuard"
    fi
    echo ""
}


# --- 主菜单和执行逻辑 ---
main_menu() {
    clear
    echo "=============================================="
    echo "      通用 WireGuard 智能路由管理脚本"
    echo "=============================================="
    hint "1. 安装并配置一个新的 WireGuard 接口 (wg0)"
    hint "2. 启动 / 关闭 WireGuard 接口"
    hint "3. 查看 WireGuard 状态和网络"
    hint "4. 卸载 WireGuard 接口"
    hint "0. 退出脚本"
    echo "----------------------------------------------"
    reading "请输入选项 [0-4]: " choice

    case "$choice" in
        1) install_wg ;;
        2) on_off ;;
        3) show_status ;;
        4) uninstall_wg ;;
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
