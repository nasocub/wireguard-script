#!/usr/bin/env bash

# 当前脚本版本号
VERSION='1.0.10' # 版本号更新，修复卸载时UFW端口清理问题

# 环境变量用于在Debian或Ubuntu操作系统中设置非交互式（noninteractive）安装模式
export DEBIAN_FRONTEND=noninteractive

# --- 脚本内部工具函数 ---

# 自定义字体彩色
warning() { echo -e "\033[31m\033[01m$*\033[0m"; }  # 红色
error() { echo -e "\033[31m\033[01m$*\033[0m" && exit 1; }  # 红色
info() { echo -e "\033[32m\033[01m$*\033[0m"; }    # 绿色
hint() { echo -e "\033[33m\033[01m$*\033[0m"; }    # 黄色
reading() { read -rp "$(info "$1")" "$2"; }

# 确保以root权限运行
check_root() {
  [ "$(id -u)" != 0 ] && error "此脚本必须以root权限运行。请使用 sudo -i 后再次运行。"
}

# 检查操作系统
check_operating_system() {
  if [ -s /etc/os-release ]; then
    SYS="$(grep -i pretty_name /etc/os-release | cut -d \" -f2)"
  elif [ -x "$(type -p hostnamectl)" ]; then
    SYS="$(hostnamectl | grep -i system | cut -d : -f2)"
  elif [ -x "$(type -p lsb_release)" ]; then
    SYS="$(lsb_release -sd)"
  elif [ -s /etc/lsb-release ]; then
    SYS="$(grep -i description /etc/lsb-release | cut -d \" -f2)"
  elif [ -s /etc/redhat-release ]; then
    SYS="$(grep . /etc/redhat-release)"
  elif [ -s /etc/issue ]; then
    SYS="$(grep . /etc/issue | cut -d '\' -f1 | sed '/^[ ]*$/d')"
  fi

  REGEX=("debian" "ubuntu" "centos|red hat|kernel|alma|rocky" "alpine" "arch linux" "fedora")
  RELEASE=("Debian" "Ubuntu" "CentOS" "Alpine" "Arch" "Fedora")
  MAJOR=("9" "16" "7" "" "" "37") # 最低支持版本
  PACKAGE_UPDATE=("apt -y update" "apt -y update" "yum -y update --skip-broken" "apk update -f" "pacman -Sy" "dnf -y update")
  PACKAGE_INSTALL=("apt -y install" "apt -y install" "yum -y install" "apk add -f" "pacman -S --noconfirm" "dnf -y install")
  PACKAGE_UNINSTALL=("apt -y autoremove" "apt -y autoremove" "yum -y autoremove" "apk del -f" "pacman -Rcnsu --noconfirm" "dnf -y autoremove")
  SYSTEMCTL_START=("systemctl start wg-quick@wg0" "systemctl start wg-quick@wg0" "systemctl start wg-quick@wg0" "wg-quick up wg0" "systemctl start wg-quick@wg0" "systemctl start wg-quick@wg0")
  SYSTEMCTL_RESTART=("systemctl restart wg-quick@wg0" "systemctl restart wg-quick@wg0" "systemctl restart wg-quick@wg0" "alpine_wg_restart" "systemctl restart wg-quick@wg0" "systemctl restart wg-quick@wg0")
  SYSTEMCTL_ENABLE=("systemctl enable --now wg-quick@wg0" "systemctl enable --now wg-quick@wg0" "systemctl enable --now wg-quick@wg0" "alpine_wg_enable" "systemctl enable --now wg-quick@wg0" "systemctl enable --now wg-quick@wg0")

  for int in "${!REGEX[@]}"; do
    [[ "${SYS,,}" =~ ${REGEX[int]} ]] && SYSTEM="${RELEASE[int]}" && break
  done

  [ -z "$SYSTEM" ] && error "不支持的操作系统: $SYS。脚本中止。"

  MAJOR_VERSION=$(sed "s/[^0-9.]//g" <<< "$SYS" | cut -d. -f1)
  [ -n "${MAJOR[int]}" ] && [[ "$MAJOR_VERSION" -lt "${MAJOR[int]}" ]] && error "当前操作系统 ${SYS} 不支持，要求版本高于 ${RELEASE[int]} ${MAJOR[int]}。"

  # Alpine specific functions
  alpine_wg_restart() { wg-quick down wg0 >/dev/null 2>&1; wg-quick up wg0 >/dev/null 2>&1; }
  alpine_wg_enable() { echo -e "wg-quick up wg0" > /etc/local.d/wg0.start; chmod +x /etc/local.d/wg0.start; rc-update add local; wg-quick up wg0 >/dev/null 2>&1; }
}

# 安装系统依赖
check_dependencies() {
  info "\n检查并安装系统依赖..."

  if [ "$SYSTEM" = 'Alpine' ]; then
    DEPS_CHECK=("ping" "curl" "grep" "bash" "ip" "wget" "resolvconf" "iptables" "ip6tables") # Add iptables/ip6tables check
    DEPS_INSTALL=("iputils-ping" "curl" "grep" "bash" "iproute2" "wget" "openresolv" "iptables" "iptables") # Add iptables/ip6tables to install list
  else
    DEPS_CHECK=("ping" "wget" "curl" "systemctl" "ip" "resolvconf" "iptables" "ip6tables" "ufw") # Add iptables/ip6tables and ufw check
    DEPS_INSTALL=("iputils-ping" "wget" "curl" "systemctl" "iproute2" "openresolv" "iptables" "iptables" "ufw") # Add iptables/ip6tables and ufw to install list
  fi

  local DEPS_TO_INSTALL=()
  for g in "${!DEPS_CHECK[@]}"; do
    # For resolvconf, check if command exists, not package. Package name might vary.
    if [ "${DEPS_CHECK[g]}" = "resolvconf" ]; then
      if ! command -v resolvconf >/dev/null 2>&1; then
        DEPS_TO_INSTALL+=(${DEPS_INSTALL[g]})
      fi
    elif [ ! -x "$(type -p ${DEPS_CHECK[g]})" ]; then
      DEPS_TO_INSTALL+=(${DEPS_INSTALL[g]})
    fi
  done

  if [ "${#DEPS_TO_INSTALL[@]}" -ge 1 ]; then
    info "正在安装以下依赖: ${DEPS_TO_INSTALL[@]}"
    ${PACKAGE_UPDATE[int]} >/dev/null 2>&1 || warning "更新软件包列表失败，尝试继续安装依赖。"
    ${PACKAGE_INSTALL[int]} ${DEPS_TO_INSTALL[@]} >/dev/null 2>&1 || error "安装依赖失败，脚本中止。"
  else
    info "所有依赖已存在，无需额外安装。"
  fi

  # 安装 wireguard-tools
  if [ ! -x "$(type -p wg)" ]; then
    info "安装 wireguard-tools..."
    case "$SYSTEM" in
      Debian )
        local DEBIAN_VERSION=$(echo $SYS | sed "s/[^0-9.]//g" | cut -d. -f1)
        if [ "$DEBIAN_VERSION" -lt 11 ]; then # Debian 9/10 需要 backports
          echo "deb http://deb.debian.org/debian $(awk -F '=' '/VERSION_CODENAME/{print $2}' /etc/os-release)-backports main" > /etc/apt/sources.list.d/backports.list
          ${PACKAGE_UPDATE[int]} >/dev/null 2>&1
        fi
        ${PACKAGE_INSTALL[int]} wireguard-tools || error "wireguard-tools 安装失败。"
        ;;
      Ubuntu )
        ${PACKAGE_INSTALL[int]} wireguard-tools || error "wireguard-tools 安装失败。"
        ;;
      CentOS|Fedora )
        [ "$SYSTEM" = 'CentOS' ] && ${PACKAGE_INSTALL[int]} epel-release >/dev/null 2>&1
        ${PACKAGE_INSTALL[int]} wireguard-tools || error "wireguard-tools 安装失败。"
        ;;
      Alpine )
        ${PACKAGE_INSTALL[int]} wireguard-tools || error "wireguard-tools 安装失败。"
        ;;
      Arch )
        ${PACKAGE_INSTALL[int]} wireguard-tools || error "wireguard-tools 安装失败。"
        ;;
      * )
        error "无法为当前操作系统安装 wireguard-tools，请手动安装。"
    esac
  fi

  # 确保防火墙规则持久化工具安装
  if [ "$SYSTEM" = 'Debian' ] || [ "$SYSTEM" = 'Ubuntu' ]; then
    if ! dpkg -s netfilter-persistent >/dev/null 2>&1; then
      info "安装 netfilter-persistent 以保存防火墙规则..."
      ${PACKAGE_INSTALL[int]} netfilter-persistent >/dev/null 2>&1 || warning "netfilter-persistent 安装失败，防火墙规则可能无法持久化。"
      systemctl enable netfilter-persistent >/dev/null 2>&1 || warning "启用 netfilter-persistent 失败。"
    fi
  elif [ "$SYSTEM" = 'CentOS' ] || [ "$SYSTEM" = 'Fedora' ]; then
    if ! rpm -q iptables-services >/dev/null 2>&1; then
      info "安装 iptables-services 以保存防火墙规则..."
      ${PACKAGE_INSTALL[int]} iptables-services >/dev/null 2>&1 || warning "iptables-services 安装失败，防火墙规则可能无法持久化。"
      systemctl enable iptables >/dev/null 2>&1
      systemctl enable ip6tables >/dev/null 2>&1
    fi
  fi

  PING6='ping -6' && [ -x "$(type -p ping6)" ] && PING6='ping6'
}

# 获取服务器当前公网 IP，优先通过路由表获取
get_public_ips() {
    # Get the source IP that would be used for reaching a well-known public IPv4 address
    PUBLIC_V4=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $NF; exit}' | grep -Eo '^([0-9]{1,3}\.){3}[0-9]{1,3}$')
    # Get the source IP that would be used for reaching a well-known public IPv6 address
    # Use a common IPv6 DNS server like Cloudflare or Google
    PUBLIC_V6=$(ip -6 route get 2606:4700:4700::1111 2>/dev/null | awk '{print $NF; exit}' | grep -Eo '^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$')
    PUBLIC_V6_INTERFACE=$(ip -6 route get 2606:4700:4700::1111 2>/dev/null | awk '{for(i=1;i<=NF;++i) if ($i=="dev") { print $(i+1); exit; }}')

    # Fallback to ip addr show if ip route get doesn't work (e.g., no default route, or for link-local addresses)
    [ -z "$PUBLIC_V4" ] && PUBLIC_V4=$(ip -4 addr show | grep 'global' | awk '{print $2}' | cut -d/ -f1 | head -n 1)
    # For IPv6, ensure we get a global scope address and not link-local
    [ -z "$PUBLIC_V6" ] && PUBLIC_V6=$(ip -6 addr show | grep 'global' | grep -v 'fe80::' | awk '{print $2}' | cut -d/ -f1 | head -n 1)
    [ -z "$PUBLIC_V6_INTERFACE" ] && PUBLIC_V6_INTERFACE=$(ip -6 addr show | grep 'global' | grep -v 'fe80::' | awk '{print $NF}' | head -n 1)
}


# 获取 WireGuard 接口的 IP (在激活后)
get_wg_interface_ips() {
    WG_LOCAL_V4=$(ip addr show wg0 | grep "inet\b" | awk '{print $2}' | cut -d / -f 1 | head -n 1)
    WG_LOCAL_V6=$(ip addr show wg0 | grep "inet6\b" | awk '{print $2}' | cut -d / -f 1 | head -n 1)
}

# 安装自定义 WireGuard VPN
install_custom_wireguard() {
  info "\n--- 安装自定义 WireGuard VPN ---"

  [ -e /etc/wireguard/wg0.conf ] && warning "已检测到现有 WireGuard 配置 (/etc/wireguard/wg0.conf)。请先卸载旧配置或备份。" && return

  # 收集用户输入
  reading "请输入您的 WireGuard 私钥 (PrivateKey): " PRIVATE_KEY
  [ -z "$PRIVATE_KEY" ] && error "私钥不能为空！"

  reading "请输入您的 WireGuard IPv4 地址 (例如: 10.0.0.2/24): " CUSTOM_IPV4_ADDRESS
  [ -z "$CUSTOM_IPV4_ADDRESS" ] && error "IPv4 地址不能为空！"

  reading "请输入您的 WireGuard IPv6 地址 (可选，例如: fc00::2/64): " CUSTOM_IPV6_ADDRESS

  reading "请输入对端公钥 (Peer PublicKey): " PEER_PUBLIC_KEY
  [ -z "$PEER_PUBLIC_KEY" ] && error "对端公钥不能为空！"

  reading "请输入对端端点 (Endpoint, 例如: vpn.example.com:51820): " ENDPOINT
  [ -z "$ENDPOINT" ] && error "端点不能为空！"

  reading "请输入预共享密钥 (PresharedKey, 可选，留空则不使用): " PRESHARED_KEY

  reading "请输入持久连接间隔 (PersistentKeepalive, 可选，秒，留空则不使用): " PERSISTENT_KEEPALIVE

  reading "请输入 WireGuard MTU 值 (可选，推荐 1420，留空则不设置): " CUSTOM_MTU

  # 启用 IP 转发功能
  info "启用 IP 转发功能..."
  # 启用 IPv4 转发
  echo "net.ipv4.ip_forward = 1" | tee /etc/sysctl.d/99-wireguard-forwarding.conf > /dev/null
  # 如果检测到原生 IPv6，则启用 IPv6 转发
  if [ -n "$PUBLIC_V6" ]; then
      echo "net.ipv6.conf.all.forwarding = 1" | tee -a /etc/sysctl.d/99-wireguard-forwarding.conf > /dev/null
      echo "net.ipv6.conf.default.forwarding = 1" | tee -a /etc/sysctl.d/99-wireguard-forwarding.conf > /dev/null
      info "IPv6 转发已启用并设置为开机启动。"
  else
      warning "未检测到原生公共 IPv6 地址，跳过 IPv6 转发配置。"
  fi
  sysctl -p /etc/sysctl.d/99-wireguard-forwarding.conf >/dev/null 2>&1 || warning "应用 sysctl 配置失败，请手动检查 /etc/sysctl.d/99-wireguard-forwarding.conf。"


  # 处理 UFW 防火墙规则
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
      info "检测到 UFW 处于活动状态，正在配置 UFW 规则..."
      # 允许 WireGuard 接口的流量转发
      ufw allow in on wg0 comment 'Allow WireGuard inbound traffic'
      ufw allow out on wg0 comment 'Allow WireGuard outbound traffic'
      # 允许 WireGuard 端口 UDP 流量
      # 此处假设 WireGuard 监听端口为 51820 (如果您配置了不同的端口，请修改)
      local ENDPOINT_PORT=$(echo "$ENDPOINT" | awk -F':' '{print $NF}')
      ufw allow $ENDPOINT_PORT/udp comment "Allow WireGuard UDP traffic"
      # 允许转发策略从 DROP 改为 ACCEPT (如果默认是 DROP)
      sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
      ufw reload >/dev/null 2>&1 || warning "UFW 重载失败，请手动检查。"
      info "UFW 规则已配置。请注意，如果您之前有其他严格的 UFW 规则，可能需要手动调整以允许相关流量。"
  else
      info "未检测到 UFW 或 UFW 未启用，跳过 UFW 配置。"
  fi


  # 创建 WireGuard 配置文件
  mkdir -p /etc/wireguard/

  cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = $PRIVATE_KEY
Address = $CUSTOM_IPV4_ADDRESS
EOF

  # 只有当用户输入了 IPv6 地址且 VPS 本身有原生 IPv6 时，才将 IPv6 地址写入配置
  if [ -n "$CUSTOM_IPV6_ADDRESS" ] && [ -n "$PUBLIC_V6" ]; then
      echo "Address = $CUSTOM_IPV6_ADDRESS" >> /etc/wireguard/wg0.conf
      info "VPS 检测到原生 IPv6。WireGuard IPv6 地址已写入配置。"
  elif [ -n "$CUSTOM_IPV6_ADDRESS" ]; then
      warning "VPS 未检测到原生 IPv6。WireGuard IPv6 地址将被忽略以防止启动错误。"
  fi

  # 使用公共 DNS 服务
  echo "DNS = 1.1.1.1, 8.8.8.8, 2606:4700:4700::1111, 2001:4860:4860::8888" >> /etc/wireguard/wg0.conf

  # 设置 WireGuard 接口的 MTU
  [ -n "$CUSTOM_MTU" ] && echo "MTU = $CUSTOM_MTU" >> /etc/wireguard/wg0.conf

  # 配置 PostUp/PostDown 脚本以实现选择性路由
  # 目标：入站流量和来自本地服务的出站流量不受影响，其他出站流量走 WireGuard。
  echo "PostUp = /etc/wireguard/wg0_up.sh" >> /etc/wireguard/wg0.conf
  echo "PostDown = /etc/wireguard/wg0_down.sh" >> /etc/wireguard/wg0.conf
  echo "Table = off" >> /etc/wireguard/wg0.conf # 不直接修改主路由表，而是通过 PostUp/PostDown 管理

  cat >> /etc/wireguard/wg0.conf <<EOF

[Peer]
PublicKey = $PEER_PUBLIC_KEY
Endpoint = $ENDPOINT
AllowedIPs = 0.0.0.0/0
EOF

  # 只有当 VPS 有原生 IPv6 并且用户输入了 WireGuard IPv6 地址时，才添加 IPv6 的 AllowedIPs
  if [ -n "$CUSTOM_IPV6_ADDRESS" ] && [ -n "$PUBLIC_V6" ]; then
      echo "AllowedIPs = ::/0" >> /etc/wireguard/wg0.conf
  fi

  [ -n "$PRESHARED_KEY" ] && echo "PresharedKey = $PRESHARED_KEY" >> /etc/wireguard/wg0.conf
  [ -n "$PERSISTENT_KEEPALIVE" ] && echo "PersistentKeepalive = $PERSISTENT_KEEPALIVE" >> /etc/wireguard/wg0.conf

  chmod 600 /etc/wireguard/wg0.conf

  info "WireGuard 配置文件已创建: /etc/wireguard/wg0.conf"

  # 创建 PostUp 脚本 (wg0_up.sh)
  # 目标:
  # 1. 确保来自 VPS 公网 IP 的流量（入站响应）使用主路由表。
  # 2. 将来自 WireGuard 隧道内部 IP 的流量路由到自定义表。
  # 3. 将其他（未明确指定）的出站流量通过 WireGuard 隧道。

  cat > /etc/wireguard/wg0_up.sh <<EOF
#!/usr/bin/env bash
# 此脚本用于 WireGuard 接口启动后配置路由规则

# 默认启用调试模式 (方便排查问题)
set -x

# 获取服务器当前公网 IP 和接口
get_public_ips_in_up_script() {
    # 通过查询默认路由来获取主要的出站接口
    PUBLIC_V4_INTERFACE_IN_UP=\$(ip -4 route | grep default | awk '{print \$5; exit}')
    PUBLIC_V6_INTERFACE_IN_UP=\$(ip -6 route | grep default | awk '{print \$5; exit}')

    # 获取公共 IPv4 和 IPv6 地址
    PUBLIC_V4_IN_UP=\$(ip route get 8.8.8.8 2>/dev/null | awk '{print \$NF; exit}' | grep -Eo '^([0-9]{1,3}\.){3}[0-9]{1,3}\$')
    PUBLIC_V6_IN_UP=\$(ip -6 route get 2606:4700:4700::1111 2>/dev/null | awk '{print \$NF; exit}' | grep -Eo '^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}\$')

    # Fallback for IP addresses if ip route get doesn't work
    [ -z "\$PUBLIC_V4_IN_UP" ] && PUBLIC_V4_IN_UP=\$(ip -4 addr show | grep 'global' | awk '{print \$2}' | cut -d/ -f1 | head -n 1)
    [ -z "\$PUBLIC_V6_IN_UP" ] && PUBLIC_V6_IN_UP=\$(ip -6 addr show | grep 'global' | grep -v 'fe80::' | awk '{print \$2}' | cut -d/ -f1 | head -n 1)

    # Fallback for interfaces if default route is not found or has no interface
    [ -z "\$PUBLIC_V4_INTERFACE_IN_UP" ] && PUBLIC_V4_INTERFACE_IN_UP=\$(ip -4 addr show | grep 'global' | awk '{print \$NF}' | head -n 1)
    [ -z "\$PUBLIC_V6_INTERFACE_IN_UP" ] && PUBLIC_V6_INTERFACE_IN_UP=\$(ip -6 addr show | grep 'global' | grep -v 'fe80::' | awk '{print \$NF}' | head -n 1)
}
get_public_ips_in_up_script

echo "Debug (wg0_up.sh): PUBLIC_V4_IN_UP = \$PUBLIC_V4_IN_UP"
echo "Debug (wg0_up.sh): PUBLIC_V6_IN_UP = \$PUBLIC_V6_IN_UP"
echo "Debug (wg0_up.sh): PUBLIC_V4_INTERFACE_IN_UP = \$PUBLIC_V4_INTERFACE_IN_UP"
echo "Debug (wg0_up.sh): PUBLIC_V6_INTERFACE_IN_UP = \$PUBLIC_V6_INTERFACE_IN_UP"


# 循环等待 wg0 接口和其 IPv4/IPv6 地址就绪
ATTEMPTS=0
MAX_ATTEMPTS=15 # 增加尝试次数，总等待时间为 15 * 2 = 30 秒
SLEEP_INTERVAL=2

WG_LOCAL_V4=""
WG_LOCAL_V6=""

echo "Debug (wg0_up.sh): 等待 wg0 接口获取 IP 地址..."

while [ -z "\$WG_LOCAL_V4" ] && [ \$ATTEMPTS -lt \$MAX_ATTEMPTS ]; do
    WG_LOCAL_V4=\$(ip addr show wg0 | grep "inet\b" | awk '{print \$2}' | cut -d / -f 1 | head -n 1)
    if [ -z "\$WG_LOCAL_V4" ]; then
        echo "Debug (wg0_up.sh): 尝试 \$((ATTEMPTS+1))/\$MAX_ATTEMPTS: IPv4 地址未就绪，等待 \$SLEEP_INTERVAL 秒..."
        sleep \$SLEEP_INTERVAL
        ATTEMPTS=\$((ATTEMPTS+1))
    fi
done

if [ -n "\$PUBLIC_V6_IN_UP" ]; then
    ATTEMPTS=0 # 重置尝试次数
    while [ -z "\$WG_LOCAL_V6" ] && [ \$ATTEMPTS -lt \$MAX_ATTEMPTS ]; do
        WG_LOCAL_V6=\$(ip addr show wg0 | grep "inet6\b" | awk '{print \$2}' | cut -d / -f 1 | head -n 1)
        # 确保获取到的是非 link-local 地址
        if [[ "\$WG_LOCAL_V6" =~ ^fe80:: ]]; then
            WG_LOCAL_V6="" # 忽略 link-local 地址
        fi

        if [ -z "\$WG_LOCAL_V6" ]; then
            echo "Debug (wg0_up.sh): 尝试 \$((ATTEMPTS+1))/\$MAX_ATTEMPTS: IPv6 地址未就绪，等待 \$SLEEP_INTERVAL 秒..."
            sleep \$SLEEP_INTERVAL
            ATTEMPTS=\$((ATTEMPTS+1))
        fi
    done
fi

echo "Debug (wg0_up.sh): WG_LOCAL_V4 = \$WG_LOCAL_V4"
echo "Debug (wg0_up.sh): WG_LOCAL_V6 = \$WG_LOCAL_V6"

if [ -z "\$WG_LOCAL_V4" ]; then
    echo "错误 (wg0_up.sh): 无法获取 wg0 的 IPv4 地址，WireGuard 可能未正确启动或超时。" >&2
    exit 1
fi

# 定义自定义路由表 51820
# (如果不存在则添加，避免重复添加导致错误)
grep -q '51820\s\+wg_custom' /etc/iproute2/rt_tables || echo '51820   wg_custom' >> /etc/iproute2/rt_tables

# 清理可能存在的旧规则，确保幂等性
echo "Debug (wg0_up.sh): 清理旧的 IP 规则和路由..."
ip rule del table main suppress_prefixlength 0 pref 50 2>/dev/null
ip rule del table 51820 suppress_prefixlength 0 2>/dev/null
[ -n "\$WG_LOCAL_V4" ] && ip -4 rule del from \$WG_LOCAL_V4 lookup 51820 pref 200 2>/dev/null
[ -n "\$WG_LOCAL_V6" ] && ip -6 rule del from \$WG_LOCAL_V6 lookup 51820 pref 200 2>/dev/null
ip -4 route del default dev wg0 table 51820 2>/dev/null
[ -n "\$WG_LOCAL_V6" ] && ip -6 route del default dev wg0 table 51820 2>/dev/null
[ -n "\$PUBLIC_V4_IN_UP" ] && ip -4 rule del from \$PUBLIC_V4_IN_UP lookup main pref 100 2>/dev/null
[ -n "\$PUBLIC_V6_IN_UP" ] && ip -6 rule del from \$PUBLIC_V6_IN_UP lookup main pref 100 2>/dev/null
ip rule del table 51820 pref 300 2>/dev/null # 删除兜底规则，重新添加以确保顺序

# 清理 mangle 表中可能存在的 TCPMSS 规则
iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null
ip6tables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null

# 清理旧的 NAT 规则（如果存在）
# 使用获取到的接口变量进行清理，确保准确性
[ -n "\$PUBLIC_V4_INTERFACE_IN_UP" ] && iptables -t nat -D POSTROUTING -o \$PUBLIC_V4_INTERFACE_IN_UP -j MASQUERADE 2>/dev/null
[ -n "\$PUBLIC_V6_INTERFACE_IN_UP" ] && ip6tables -t nat -D POSTROUTING -o \$PUBLIC_V6_INTERFACE_IN_UP -j MASQUERADE 2>/dev/null


echo "Debug (wg0_up.sh): 添加新的 IP 规则和路由..."
# 添加新的路由规则
# 优先级：
# 1. (最高优先级) 抑制主路由表的默认路由，让自定义规则生效。
# 这样除了明确指向主表的流量外，其他流量不会默认走主表。
ip rule add table main suppress_prefixlength 0 pref 50

# 2. 确保来自 VPS 主公网 IP 的流量（入站响应）使用主路由表
[ -n "\$PUBLIC_V4_IN_UP" ] && ip -4 rule add from \$PUBLIC_V4_IN_UP lookup main pref 100
[ -n "\$PUBLIC_V6_IN_UP" ] && ip -6 rule add from \$PUBLIC_V6_IN_UP lookup main pref 100

# 3. 将来自 WireGuard 接口本地 IP 的流量路由到自定义表
# 这是为了确保 WireGuard 内部的服务可以正常出站
[ -n "\$WG_LOCAL_V4" ] && ip -4 rule add from \$WG_LOCAL_V4 lookup 51820 pref 200
[ -n "\$WG_LOCAL_V6" ] && ip -6 rule add from \$WG_LOCAL_V6 lookup 51820 pref 200

# 4. 定义自定义表 51820 的默认路由，通过 WireGuard 接口
# 这是 WireGuard 出口
ip -4 route add default dev wg0 table 51820
[ -n "\$WG_LOCAL_V6" ] && ip -6 route add default dev wg0 table 51820

# 5. (最低优先级) 兜底规则：所有未被前面规则匹配到的流量都路由到自定义表 51820
# 这确保了除本地入站响应外的所有其他出站流量都走 WireGuard
ip rule add table 51820 pref 300

# TCP MSS Clamping，优化性能
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
ip6tables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# --- 配置防火墙 NAT 链规则 (UFW现在处理FORWARD链) ---
echo "Debug (wg0_up.sh): 配置 iptables/ip6tables NAT 链规则 (FORWARD链由UFW管理)..."

# 为通过 WireGuard 接口出站的流量设置 NAT (Masquerade)
# 将来自 wg0 的内部 IP 伪装成 VPS 的公共 IP
[ -n "\$PUBLIC_V4_INTERFACE_IN_UP" ] && iptables -t nat -A POSTROUTING -o \$PUBLIC_V4_INTERFACE_IN_UP -j MASQUERADE
[ -n "\$PUBLIC_V6_INTERFACE_IN_UP" ] && ip6tables -t nat -A POSTROUTING -o \$PUBLIC_V6_INTERFACE_IN_UP -j MASQUERADE

# 额外调试：显示当前路由表和规则
echo "Debug (wg0_up.sh): 当前 IPv4 路由表 (main 和 51820):"
ip -4 route show table main
ip -4 route show table 51820
echo "Debug (wg0_up.sh): 当前 IPv6 路由表 (main 和 51820):"
ip -6 route show table main
ip -6 route show table 51820
echo "Debug (wg0_up.sh): 当前 IP 规则:"
ip rule show
echo "Debug (wg0_up.sh): 当前 iptables FORWARD 链规则:"
iptables -nvL FORWARD
echo "Debug (wg0_up.sh): 当前 iptables NAT POSTROUTING 链规则:"
iptables -t nat -nvL POSTROUTING
echo "Debug (wg0_up.sh): 当前 ip6tables FORWARD 链规则:"
ip6tables -nvL FORWARD
echo "Debug (wg0_up.sh): 当前 ip6tables NAT POSTROUTING 链规则:"
ip6tables -t nat -nvL POSTROUTING

echo "Debug (wg0_up.sh): 路由和防火墙规则应用完成。"
EOF

  chmod +x /etc/wireguard/wg0_up.sh

  # 创建 PostDown 脚本 (wg0_down.sh)
  cat > /etc/wireguard/wg0_down.sh <<EOF
#!/usr/bin/env bash
# 此脚本用于 WireGuard 接口停止后清理路由规则

# 获取服务器当前公网 IP 和接口
get_public_ips_in_down_script() {
    PUBLIC_V4_INTERFACE_IN_DOWN=\$(ip -4 route | grep default | awk '{print \$5; exit}')
    PUBLIC_V6_INTERFACE_IN_DOWN=\$(ip -6 route | grep default | awk '{print \$5; exit}')

    PUBLIC_V4_IN_DOWN=\$(ip route get 8.8.8.8 2>/dev/null | awk '{print \$NF; exit}' | grep -Eo '^([0-9]{1,3}\.){3}[0-9]{1,3}\$')
    PUBLIC_V6_IN_DOWN=\$(ip -6 route get 2606:4700:4700::1111 2>/dev/null | awk '{print \$NF; exit}' | grep -Eo '^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}\$')

    [ -z "\$PUBLIC_V4_IN_DOWN" ] && PUBLIC_V4_IN_DOWN=\$(ip -4 addr show | grep 'global' | awk '{print \$2}' | cut -d/ -f1 | head -n 1)
    [ -z "\$PUBLIC_V6_IN_DOWN" ] && PUBLIC_V6_IN_DOWN=\$(ip -6 addr show | grep 'global' | grep -v 'fe80::' | awk '{print \$2}' | cut -d/ -f1 | head -n 1)

    [ -z "\$PUBLIC_V4_INTERFACE_IN_DOWN" ] && PUBLIC_V4_INTERFACE_IN_DOWN=\$(ip -4 addr show | grep 'global' | awk '{print \$NF}' | head -n 1)
    [ -z "\$PUBLIC_V6_INTERFACE_IN_DOWN" ] && PUBLIC_V6_INTERFACE_IN_DOWN=\$(ip -6 addr show | grep 'global' | grep -v 'fe80::' | awk '{print \$NF}' | head -n 1)
}
get_public_ips_in_down_script


# 获取 WireGuard 接口的 IP (可能已失效，但尝试获取用于清理旧规则)
WG_LOCAL_V4=\$(ip addr show wg0 | grep "inet\b" | awk '{print \$2}' | cut -d / -f 1 | head -n 1)
# 只有当 VPS 有原生 IPv6 时才尝试获取 wg0 的本地 IPv6 地址
[ -n "\$PUBLIC_V6_IN_DOWN" ] && WG_LOCAL_V6=\$(ip addr show wg0 | grep "inet6\b" | awk '{print \$2}' | cut -d / -f 1 | head -n 1)


# 删除自定义路由表规则 (确保删除顺序正确，与 PostUp 相反)
iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null
ip6tables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null

# 清理 NAT 规则
[ -n "\$PUBLIC_V4_INTERFACE_IN_DOWN" ] && iptables -t nat -D POSTROUTING -o \$PUBLIC_V4_INTERFACE_IN_DOWN -j MASQUERADE 2>/dev/null
[ -n "\$PUBLIC_V6_INTERFACE_IN_DOWN" ] && ip6tables -t nat -D POSTROUTING -o \$PUBLIC_V6_INTERFACE_IN_DOWN -j MASQUERADE 2>/dev/null


ip rule del table 51820 pref 300 2>/dev/null

ip -4 route del default dev wg0 table 51820 2>/dev/null
[ -n "\$WG_LOCAL_V6" ] && ip -6 route del default dev wg0 table 51820 2>/dev/null

[ -n "\$WG_LOCAL_V4" ] && ip -4 rule del from \$WG_LOCAL_V4 lookup 51820 pref 200 2>/dev/null
[ -n "\$WG_LOCAL_V6" ] && ip -6 rule del from \$WG_LOCAL_V6 lookup 51820 pref 200 2>/dev/null

[ -n "\$PUBLIC_V4_IN_DOWN" ] && ip -4 rule del from \$PUBLIC_V4_IN_DOWN lookup main pref 100 2>/dev/null
[ -n "\$PUBLIC_V6_IN_DOWN" ] && ip -6 rule del from \$PUBLIC_V6_IN_DOWN lookup main pref 100 2>/dev/null

ip rule del table main suppress_prefixlength 0 pref 50 2>/dev/null
ip rule del table 51820 suppress_prefixlength 0 2>/dev/null


# 删除自定义路由表名
sed -i '/51820\s\+wg_custom/d' /etc/iproute2/rt_tables 2>/dev/null
EOF

  chmod +x /etc/wireguard/wg0_down.sh

  info "WireGuard 启动/停止脚本已创建: /etc/wireguard/wg0_up.sh 和 /etc/wireguard/wg0_down.sh"

  # 启用并启动 WireGuard 服务
  ${SYSTEMCTL_ENABLE[int]} >/dev/null 2>&1 || error "启用 WireGuard 服务失败，请检查日志。"
  ${SYSTEMCTL_START[int]} >/dev/null 2>&1 || error "启动 WireGuard 服务失败，请检查日志。"

  info "\n--- 自定义 WireGuard VPN 安装成功！ ---"
  get_status
}

# 检查自定义 WireGuard VPN 状态
get_status() {
  info "\n--- 检查自定义 WireGuard VPN 状态 ---"
  if [ ! -e /etc/wireguard/wg0.conf ]; then
    warning "未检测到 WireGuard 配置文件 (/etc/wireguard/wg0.conf)。"
    return
  fi

  local STATUS=$(systemctl is-active wg-quick@wg0 2>/dev/null)
  if [ "$STATUS" = "active" ]; then
    info "WireGuard 服务状态: 运行中"
    ip addr show wg0
    echo "-----------------------------------"
    wg show wg0
    echo "-----------------------------------"
    # 直接使用全局变量 PUBLIC_V4 和 PUBLIC_V6
    info "您的 VPS 当前公网 IPv4: $PUBLIC_V4"
    if [ -n "$PUBLIC_V6" ]; then
        info "您的 VPS 当前公网 IPv6: $PUBLIC_V6"
    else
        warning "您的 VPS 未检测到原生公共 IPv6 地址。"
    fi

    info "通过 wg0 隧道出站的 IP (如果成功):"
    # Ensure curl uses the wg0 interface for these checks
    curl -s4 --interface wg0 ipinfo.io/ip || echo "  (IPv4 未获取到或未通过 wg0 隧道)"
    if [ -n "$PUBLIC_V6" ]; then # 只有当 VPS 有原生 IPv6 时才尝试检测 IPv6 隧道
        # 为 curl -s6 命令添加超时，避免长时间卡住
        curl -s6 --interface wg0 --max-time 10 ipinfo.io/ip || echo "  (IPv6 未获取到或未通过 wg0 隧道)"
    else
        echo "  (VPS 未检测到原生 IPv6，跳过隧道 IPv6 检测)"
    fi
    echo "注意：出站 IP 显示的是通过 wg0 隧道的IP，入站流量仍会走您的原生IP。"
  else
    warning "WireGuard 服务状态: 未运行或出现错误。"
    warning "请尝试启动 (选项 3) 或检查日志。"
  fi
}

# 开启/关闭自定义 WireGuard VPN
toggle_wireguard() {
  info "\n--- 开启/关闭自定义 WireGuard VPN ---"
  if [ ! -e /etc/wireguard/wg0.conf ]; then
    warning "未检测到 WireGuard 配置。请先安装 (选项 1)。"
    return
  fi

  local STATUS=$(systemctl is-active wg-quick@wg0 2>/dev/null)
  if [ "$STATUS" = "active" ]; then
    info "正在关闭 WireGuard 服务..."
    # For Alpine, wg-quick down wg0 is sufficient as there's no systemd unit for it directly
    [ "$SYSTEM" = Alpine ] && wg-quick down wg0 >/dev/null 2>&1 || systemctl stop wg-quick@wg0 >/dev/null 2>&1
    info "WireGuard 已关闭。"
  else
    info "正在开启 WireGuard 服务..."
    ${SYSTEMCTL_START[int]} >/dev/null 2>&1
    info "WireGuard 已开启。"
  fi
  get_status
}

# 卸载自定义 WireGuard VPN
uninstall_wireguard() {
  info "\n--- 卸载自定义 WireGuard VPN ---"
  if [ ! -e /etc/wireguard/wg0.conf ]; then
    warning "未检测到 WireGuard 配置，无需卸载。"
    return
  fi

  # 默认启用调试模式 (方便排查问题)
  set -x # Enable debugging for uninstall function

  # 尝试从配置文件中读取ENDPOINT，用于清理UFW规则
  local UNINSTALL_ENDPOINT=""
  if [ -s /etc/wireguard/wg0.conf ]; then
      UNINSTALL_ENDPOINT=$(grep "Endpoint" /etc/wireguard/wg0.conf | awk -F'= ' '{print $2}' | tr -d '[:space:]')
      echo "Debug (uninstall_wireguard): Detected Endpoint from config: $UNINSTALL_ENDPOINT"
  fi

  info "正在停止并禁用 WireGuard 服务..."
  [ "$SYSTEM" = Alpine ] && wg-quick down wg0 >/dev/null 2>&1 || systemctl stop wg-quick@wg0 >/dev/null 2>&1
  [ "$SYSTEM" = Alpine ] && rc-update del local default 2>/dev/null || systemctl disable wg-quick@wg0 >/dev/null 2>&1

  info "正在删除 WireGuard 配置文件和脚本..."
  rm -f /etc/wireguard/wg0.conf
  rm -f /etc/wireguard/wg0_up.sh
  rm -f /etc/wireguard/wg0_down.sh

  # 删除自定义路由表名
  sed -i '/51820\s\+wg_custom/d' /etc/iproute2/rt_tables 2>/dev/null

  # 删除 IP 转发的 sysctl 配置
  rm -f /etc/sysctl.d/99-wireguard-forwarding.conf
  sysctl --system >/dev/null 2>&1 # 重新加载所有 sysctl 配置，移除此脚本添加的转发规则

  # 清理 UFW 规则
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
      info "正在清理 UFW 规则..."
      # 移除 WireGuard 接口的流量转发规则
      ufw delete allow in on wg0 comment 'Allow WireGuard inbound traffic' 2>/dev/null
      ufw delete allow out on wg0 comment 'Allow WireGuard outbound traffic' 2>/dev/null
      # 移除 WireGuard UDP 端口规则
      local UNINSTALL_ENDPOINT_PORT=""
      if [ -n "$UNINSTALL_ENDPOINT" ]; then
          UNINSTALL_ENDPOINT_PORT=$(echo "$UNINSTALL_ENDPOINT" | awk -F':' '{print $NF}')
          echo "Debug (uninstall_wireguard): Endpoint Port for cleanup: $UNINSTALL_ENDPOINT_PORT"
          ufw delete allow $UNINSTALL_ENDPOINT_PORT/udp comment "Allow WireGuard UDP traffic" 2>/dev/null
      else
          warning "无法从配置文件获取WireGuard端口，请手动检查UFW规则以确保端口清理。"
      fi
      
      # 恢复 UFW 的转发策略 (如果之前是 ACCEPT)
      # 仅在检测到当前为 ACCEPT 时才改回 DROP，避免影响用户其他配置
      if grep -q 'DEFAULT_FORWARD_POLICY="ACCEPT"' /etc/default/ufw; then
          sed -i 's/DEFAULT_FORWARD_POLICY="ACCEPT"/DEFAULT_FORWARD_POLICY="DROP"/' /etc/default/ufw
          info "UFW DEFAULT_FORWARD_POLICY 已尝试恢复为 DROP。"
      fi
      ufw reload >/dev/null 2>&1 || warning "UFW 重载失败，请手动检查。"
      info "UFW 规则已清理。请手动检查 /etc/default/ufw 中的 DEFAULT_FORWARD_POLICY。"
  fi

  # 尝试卸载 wireguard-tools 依赖 (可选，但为了清理)
  reading "是否卸载 wireguard-tools 软件包？ (y/N): " UNINSTALL_DEPS_CONFIRM
  if [[ "${UNINSTALL_DEPS_CONFIRM,,}" = "y" ]]; then
    info "正在卸载 wireguard-tools..."
    ${PACKAGE_UNINSTALL[int]} wireguard-tools >/dev/null 2>&1 || warning "卸载 wireguard-tools 失败，请手动检查。"
    # 同时卸载 openresolv，如果它是作为依赖安装的
    if command -v apt >/dev/null; then
        sudo apt autoremove --purge openresolv -y >/dev/null 2>&1 || warning "卸载 openresolv 失败，请手动检查。"
    elif command -v yum >/dev/null || command -v dnf >/dev/null; then
        sudo yum autoremove openresolv -y >/dev/null 2>&1 || sudo dnf autoremove openresolv -y >/dev/null 2>&1 || warning "卸载 openresolv 失败，请手动检查。"
    elif command -v apk >/dev/null; then
        sudo apk del openresolv >/dev/null 2>&1 || warning "卸载 openresolv 失败，请手动检查。"
    elif command -v pacman >/dev/null; then
        sudo pacman -Rcnsu openresolv --noconfirm >/dev/null 2>&1 || warning "卸载 openresolv 失败，请手动检查。"
    fi
  fi

  info "WireGuard 已彻底卸载。"
  # 直接使用全局变量 PUBLIC_V4 和 PUBLIC_V6
  info "您的 VPS 当前公网 IPv4: $PUBLIC_V4"
  if [ -n "$PUBLIC_V6" ]; then
      info "您的 VPS 当前公网 IPv6: $PUBLIC_V6"
  else
      warning "您的 VPS 未检测到原生公共 IPv6 地址。"
  fi
}

# 主菜单
menu() {
  clear
  info "--- 自定义 WireGuard VPN 管理脚本 v$VERSION ---"
  echo ""
  info "当前操作系统: $SYS"
  info "内核版本: $(uname -r)"
  echo ""
  # 确保 PUBLIC_V4 和 PUBLIC_V6 在此之前被 get_public_ips 填充
  # 这里不调用 get_status，直接显示公共 IP，因为 get_status 内部会再次检查 WireGuard 状态
  # 并在 menu() 顶部已调用 get_public_ips
  info "您的 VPS 当前公网 IPv4: ${PUBLIC_V4:-'未检测到'}"
  if [ -n "$PUBLIC_V6" ]; then
      info "您的 VPS 当前公网 IPv6: $PUBLIC_V6"
  else
      warning "您的 VPS 未检测到原生公共 IPv6 地址。"
  fi
  echo ""
  get_status # 显示 WireGuard 状态摘要
  echo ""
  info "请选择一个操作:"
  info "1. 安装自定义 WireGuard VPN"
  info "2. 获取 WireGuard VPN 状态"
  info "3. 开启/关闭 WireGuard VPN"
  info "4. 卸载 WireGuard VPN"
  info "0. 退出脚本"
  reading "\n请输入您的选择: " CHOICE

  case "$CHOICE" in
    1)
      install_custom_wireguard
      ;;
    2)
      get_status
      ;;
    3)
      toggle_wireguard
      ;;
    4) # <-- 新增：处理选项 4
      uninstall_wireguard
      ;;
    0)
      info "退出脚本。再见！"
      exit 0
      ;;
    *)
      warning "无效的选择，请重新输入。"
      ;;
  esac
  info "\n按任意键返回主菜单..."
  read -n 1 -s
  menu
}

# --- 脚本入口点 ---

check_root
check_operating_system
check_dependencies
get_public_ips # 确保在脚本开始时就获取 VPS 的公网 IP
menu
