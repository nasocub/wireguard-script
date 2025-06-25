#!/usr/bin/env bash

# Current script version number
VERSION='1.0.17' # Version updated to handle IP detection failure during startup

# Environment variable for non-interactive installation mode in Debian or Ubuntu
export DEBIAN_FRONTEND=noninteractive

# --- Script Internal Utility Functions ---

# Custom font colors
warning() { echo -e "\033[31m\033[01m$*\033[0m"; } # Red
error() { echo -e "\033[31m\033[01m$*\033[0m" && exit 1; } # Red, and exit
info() { echo -e "\033[32m\033[01m$*\033[0m"; } # Green
hint() { echo -e "\033[33m\033[01m$*\033[0m"; } # Yellow
reading() { read -rp "$(info "$1")" "$2"; }

# Ensure script runs with root privileges
check_root() {
  [ "$(id -u)" != 0 ] && error "This script must be run with root privileges. Please use sudo -i and run again."
}

# Check operating system
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
  MAJOR=("9" "16" "7" "" "" "37") # Minimum supported version
  PACKAGE_UPDATE=("apt -y update" "apt -y update" "yum -y update --skip-broken" "apk update -f" "pacman -Sy" "dnf -y update")
  PACKAGE_INSTALL=("apt -y install" "apt -y install" "yum -y install" "apk add -f" "pacman -S --noconfirm" "dnf -y install")
  PACKAGE_UNINSTALL=("apt -y autoremove" "apt -y autoremove" "yum -y autoremove" "apk del -f" "pacman -Rcnsu --noconfirm" "dnf -y autoremove")
  SYSTEMCTL_START=("systemctl start wg-quick@wg0" "systemctl start wg-quick@wg0" "systemctl start wg-quick@wg0" "wg-quick up wg0" "systemctl start wg-quick@wg0" "systemctl start wg-quick@wg0")
  SYSTEMCTL_RESTART=("systemctl restart wg-quick@wg0" "systemctl restart wg-quick@wg0" "systemctl restart wg-quick@wg0" "alpine_wg_restart" "systemctl restart wg-quick@wg0" "systemctl restart wg-quick@wg0")
  SYSTEMCTL_ENABLE=("systemctl enable wg-quick@wg0" "systemctl enable wg-quick@wg0" "systemctl enable wg-quick@wg0" "alpine_wg_enable" "systemctl enable wg-quick@wg0" "systemctl enable wg-quick@wg0")

  for int in "${!REGEX[@]}"; do
    [[ "${SYS,,}" =~ ${REGEX[int]} ]] && SYSTEM="${RELEASE[int]}" && break
  done

  [ -z "$SYSTEM" ] && error "Unsupported operating system: $SYS. Script aborted."

  MAJOR_VERSION=$(sed "s/[^0-9.]//g" <<< "$SYS" | cut -d. -f1)
  [ -n "${MAJOR[int]}" ] && [[ "$MAJOR_VERSION" -lt "${MAJOR[int]}" ]] && error "Current operating system ${SYS} is not supported. Version required: ${RELEASE[int]} ${MAJOR[int]} or higher."

  # Alpine specific functions
  alpine_wg_restart() { wg-quick down wg0 >/dev/null 2>&1; wg-quick up wg0 >/dev/null 2>&1; }
  alpine_wg_enable() { echo -e "wg-quick up wg0" > /etc/local.d/wg0.start; chmod +x /etc/local.d/wg0.start; rc-update add local; }
}

# Install system dependencies
check_dependencies() {
  info "\nChecking and installing system dependencies..."

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
    info "Installing the following dependencies: ${DEPS_TO_INSTALL[@]}"
    ${PACKAGE_UPDATE[int]} >/dev/null 2>&1 || warning "Failed to update package list, attempting to continue installing dependencies."
    ${PACKAGE_INSTALL[int]} "${DEPS_TO_INSTALL[@]}" >/dev/null 2>&1 || error "Failed to install dependencies, script aborted."
  else
    info "All dependencies already exist, no additional installation needed."
  fi

  # Install wireguard-tools
  if [ ! -x "$(type -p wg)" ]; then
    info "Installing wireguard-tools..."
    case "$SYSTEM" in
      Debian )
        local DEBIAN_VERSION=$(echo "$SYS" | sed "s/[^0-9.]//g" | cut -d. -f1)
        if [ "$DEBIAN_VERSION" -lt 11 ]; then # Debian 9/10 needs backports
          echo "deb http://deb.debian.org/debian $(awk -F '=' '/VERSION_CODENAME/{print $2}' /etc/os-release)-backports main" > /etc/apt/sources.list.d/backports.list
          ${PACKAGE_UPDATE[int]} >/dev/null 2>&1
        fi
        ${PACKAGE_INSTALL[int]} wireguard-tools || error "wireguard-tools installation failed."
        ;;
      Ubuntu )
        ${PACKAGE_INSTALL[int]} wireguard-tools || error "wireguard-tools installation failed."
        ;;
      CentOS|Fedora )
        [ "$SYSTEM" = 'CentOS' ] && ${PACKAGE_INSTALL[int]} epel-release >/dev/null 2>&1
        ${PACKAGE_INSTALL[int]} wireguard-tools || error "wireguard-tools installation failed."
        ;;
      Alpine )
        ${PACKAGE_INSTALL[int]} wireguard-tools || error "wireguard-tools installation failed."
        ;;
      Arch )
        ${PACKAGE_INSTALL[int]} wireguard-tools || error "wireguard-tools installation failed."
        ;;
      * )
        error "Cannot install wireguard-tools for the current operating system, please install manually."
    esac
  fi

  # Ensure firewall rule persistence tool is installed
  if [ "$SYSTEM" = 'Debian' ] || [ "$SYSTEM" = 'Ubuntu' ]; then
    if ! dpkg -s netfilter-persistent >/dev/null 2>&1; then
      info "Installing netfilter-persistent to save firewall rules..."
      ${PACKAGE_INSTALL[int]} netfilter-persistent >/dev/null 2>&1 || warning "netfilter-persistent installation failed, firewall rules may not persist."
      systemctl enable netfilter-persistent >/dev/null 2>&1 || warning "Failed to enable netfilter-persistent."
    fi
  elif [ "$SYSTEM" = 'CentOS' ] || [ "$SYSTEM" = 'Fedora' ]; then
    if ! rpm -q iptables-services >/dev/null 2>&1; then
      info "Installing iptables-services to save firewall rules..."
      ${PACKAGE_INSTALL[int]} iptables-services >/dev/null 2>&1 || warning "iptables-services installation failed, firewall rules may not persist."
      systemctl enable iptables >/dev/null 2>&1
      systemctl enable ip6tables >/dev/null 2>&1
    fi
  fi

  PING6='ping -6' && [ -x "$(type -p ping6)" ] && PING6='ping6'
}

# Get server's current public IP, prioritizing routing table
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


# Get WireGuard interface IPs (after activation)
get_wg_interface_ips() {
    WG_LOCAL_V4=$(ip addr show wg0 | grep "inet\b" | awk '{print $2}' | cut -d / -f 1 | head -n 1)
    WG_LOCAL_V6=$(ip addr show wg0 | grep "inet6\b" | awk '{print $2}' | cut -d / -f 1 | head -n 1)
}

# Install custom WireGuard VPN
install_custom_wireguard() {
  info "\n--- Installing Custom WireGuard VPN ---"

  [ -e /etc/wireguard/wg0.conf ] && warning "Existing WireGuard configuration detected (/etc/wireguard/wg0.conf). Please uninstall old config or back it up first." && return

  # Collect user input
  reading "Please enter your WireGuard Private Key (PrivateKey): " PRIVATE_KEY
  # Validate key format/length
  if [[ ! "$PRIVATE_KEY" =~ ^[A-Za-z0-9+/]{43}=?$ ]]; then
    error "Invalid Private Key format. It should be a 44-character Base64 string."
  fi

  reading "Please enter your WireGuard IPv4 address (e.g.: 10.0.0.2/24): " CUSTOM_IPV4_ADDRESS
  [ -z "$CUSTOM_IPV4_ADDRESS" ] && error "IPv4 address cannot be empty!"

  reading "Please enter your WireGuard IPv6 address (Optional, e.g.: fc00::2/64): " CUSTOM_IPV6_ADDRESS

  reading "Please enter Peer Public Key (Peer PublicKey): " PEER_PUBLIC_KEY
  [ -z "$PEER_PUBLIC_KEY" ] && error "Peer public key cannot be empty!"
  # Validate key format/length
  if [[ ! "$PEER_PUBLIC_KEY" =~ ^[A-Za-z0-9+/]{43}=?$ ]]; then
    error "Invalid Peer Public Key format. It should be a 44-character Base64 string."
  fi

  reading "Please enter Peer Endpoint (e.g.: vpn.example.com:51820): " ENDPOINT
  [ -z "$ENDPOINT" ] && error "Endpoint cannot be empty!"

  reading "Please enter PresharedKey (Optional, leave blank to not use): " PRESHARED_KEY
  if [ -n "$PRESHARED_KEY" ] && [[ ! "$PRESHARED_KEY" =~ ^[A-Za-z0-9+/]{43}=?$ ]]; then
    error "Invalid PresharedKey format. It should be a 44-character Base64 string."
  fi

  reading "Please enter PersistentKeepalive (Optional, seconds, leave blank to not use): " PERSISTENT_KEEPALIVE

  reading "Please enter WireGuard MTU value (Optional, recommended 1420, leave blank to not set): " CUSTOM_MTU

  # Enable IP forwarding
  info "Enabling IP forwarding..."
  # Enable IPv4 forwarding
  echo "net.ipv4.ip_forward = 1" | tee /etc/sysctl.d/99-wireguard-forwarding.conf > /dev/null
  # If native IPv6 detected, enable IPv6 forwarding
  if [ -n "$PUBLIC_V6" ]; then
      echo "net.ipv6.conf.all.forwarding = 1" | tee -a /etc/sysctl.d/99-wireguard-forwarding.conf > /dev/null
      echo "net.ipv6.conf.default.forwarding = 1" | tee -a /etc/sysctl.d/99-wireguard-forwarding.conf > /dev/null
      info "IPv6 forwarding enabled and set to start on boot."
  else
      warning "No native public IPv6 address detected, skipping IPv6 forwarding configuration."
  fi
  sysctl -p /etc/sysctl.d/99-wireguard-forwarding.conf >/dev/null 2>&1 || warning "Failed to apply sysctl configuration, please manually check /etc/sysctl.d/99-wireguard-forwarding.conf."


  # Handle UFW firewall rules
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
      info "UFW detected and active, configuring UFW rules..."
      # Allow traffic forwarding on WireGuard interface
      ufw allow in on wg0 comment 'Allow WireGuard inbound traffic'
      ufw allow out on wg0 comment 'Allow WireGuard outbound traffic'
      # Allow WireGuard UDP traffic on the specified port
      local ENDPOINT_PORT=$(echo "$ENDPOINT" | awk -F':' '{print $NF}')
      ufw allow "$ENDPOINT_PORT"/udp comment "Allow WireGuard UDP traffic"
      # Change forwarding policy from DROP to ACCEPT (if default is DROP)
      sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
      ufw reload >/dev/null 2>&1 || warning "UFW reload failed, please check manually."
      info "UFW rules configured. Note: If you had other strict UFW rules, you might need to adjust them manually to allow relevant traffic."
  else
    info "UFW not detected or not enabled, skipping UFW configuration."
  fi


  # Create WireGuard configuration file
  mkdir -p /etc/wireguard/

  cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = $PRIVATE_KEY
Address = $CUSTOM_IPV4_ADDRESS
EOF

  # Only write IPv6 address to config if user entered one AND VPS has native IPv6
  if [ -n "$CUSTOM_IPV6_ADDRESS" ] && [ -n "$PUBLIC_V6" ]; then
      echo "Address = $CUSTOM_IPV6_ADDRESS" >> /etc/wireguard/wg0.conf
      info "VPS detected native IPv6. WireGuard IPv6 address written to config."
  elif [ -n "$CUSTOM_IPV6_ADDRESS" ]; then
      warning "VPS did not detect native public IPv6. WireGuard IPv6 address will be ignored to prevent startup errors."
  fi

  # Use public DNS services
  echo "DNS = 1.1.1.1, 8.8.8.8, 2606:4700:4700::1111, 2001:4860:4860::8888" >> /etc/wireguard/wg0.conf

  # Set WireGuard interface MTU
  [ -n "$CUSTOM_MTU" ] && echo "MTU = $CUSTOM_MTU" >> /etc/wireguard/wg0.conf

  # Configure PostUp/PostDown scripts for selective routing
  # Goal: Inbound traffic and outbound traffic from local services are unaffected, other outbound traffic goes through WireGuard.
  echo "PostUp = /etc/wireguard/wg0_up.sh" >> /etc/wireguard/wg0.conf
  echo "PostDown = /etc/wireguard/wg0_down.sh" >> /etc/wireguard/wg0.conf
  echo "Table = off" >> /etc/wireguard/wg0.conf # Do not directly modify the main routing table, but manage via PostUp/PostDown

  cat >> /etc/wireguard/wg0.conf <<EOF

[Peer]
PublicKey = $PEER_PUBLIC_KEY
Endpoint = $ENDPOINT
AllowedIPs = 0.0.0.0/0
EOF

  # Only add IPv6 AllowedIPs if VPS has native IPv6 AND user entered WireGuard IPv6 address
  if [ -n "$CUSTOM_IPV6_ADDRESS" ] && [ -n "$PUBLIC_V6" ]; then
      echo "AllowedIPs = ::/0" >> /etc/wireguard/wg0.conf
  fi

  [ -n "$PRESHARED_KEY" ] && echo "PresharedKey = $PRESHARED_KEY" >> /etc/wireguard/wg0.conf
  [ -n "$PERSISTENT_KEEPALIVE" ] && echo "PersistentKeepalive = $PERSISTENT_KEEPALIVE" >> /etc/wireguard/wg0.conf

  chmod 600 /etc/wireguard/wg0.conf

  info "WireGuard configuration file created: /etc/wireguard/wg0.conf"

  # Create PostUp script (wg0_up.sh)
  # Goal:
  # 1. Ensure traffic from VPS public IP (inbound responses) uses the main routing table.
  # 2. Route traffic from WireGuard tunnel internal IPs to a custom table.
  # 3. Route other (unspecified) outbound traffic through the WireGuard tunnel.

  cat > /etc/wireguard/wg0_up.sh <<EOF
#!/usr/bin/env bash
# This script configures routing rules after the WireGuard interface starts

# Enable debugging. Uncomment the line below for verbose output:
# set -x
set -e # Exit immediately if a command exits with a non-zero status.

echo "--- Debugging wg0_up.sh ---"

# Get server's current public IP and interface
get_public_ips_in_up_script() {
    echo "Debug: Getting public IPs and interfaces..."
    # Attempt to get public IPs using ip route get. Add '|| true' to prevent script exit on failure.
    PUBLIC_V4_IN_UP=\$(ip route get 8.8.8.8 2>/dev/null | awk '{print \$NF; exit}' | grep -Eo '^([0-9]{1,3}\.){3}[0-9]{1,3}\$' || true)
    PUBLIC_V6_IN_UP=\$(ip -6 route get 2606:4700:4700::1111 2>/dev/null | awk '{print \$NF; exit}' | grep -Eo '^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}\$' || true)

    # Fallback for public IPs if ip route get doesn't work (e.g., no default route, or specific network configs)
    [ -z "\$PUBLIC_V4_IN_UP" ] && PUBLIC_V4_IN_UP=\$(ip -4 addr show | grep 'global' | awk '{print \$2}' | cut -d/ -f1 | head -n 1)
    [ -z "\$PUBLIC_V6_IN_UP" ] && PUBLIC_V6_IN_UP=\$(ip -6 addr show | grep 'global' | grep -v 'fe80::' | awk '{print \$2}' | cut -d/ -f1 | head -n 1)

    # If public IPs still not found, exit with an error. NAT won't work otherwise.
    if [ -z "\$PUBLIC_V4_IN_UP" ] && [ -z "\$PUBLIC_V6_IN_UP" ]; then
        echo "Error (wg0_up.sh): Failed to determine either public IPv4 or IPv6 address of the VPS after multiple attempts. Aborting." >&2
        exit 1
    fi

    # Now, try to get the interfaces using the identified public IPs (more robust)
    PUBLIC_V4_INTERFACE_IN_UP=""
    if [ -n "\$PUBLIC_V4_IN_UP" ]; then
        PUBLIC_V4_INTERFACE_IN_UP=\$(ip route get "\$PUBLIC_V4_IN_UP" 2>/dev/null | awk '{for(i=1;i<=NF;++i) if (\$i=="dev") { print \$(i+1); exit; }}' || true)
        [ -z "\$PUBLIC_V4_INTERFACE_IN_UP" ] && PUBLIC_V4_INTERFACE_IN_UP=\$(ip -4 addr show | grep "\$PUBLIC_V4_IN_UP" | awk '{print \$NF}' | head -n 1)
        if [ -z "\$PUBLIC_V4_INTERFACE_IN_UP" ]; then
            echo "Warning (wg0_up.sh): Could not determine the public IPv4 interface for NAT. IPv4 masquerading may not work correctly." >&2
        fi
    fi

    PUBLIC_V6_INTERFACE_IN_UP=""
    if [ -n "\$PUBLIC_V6_IN_UP" ]; then
        PUBLIC_V6_INTERFACE_IN_UP=\$(ip -6 route get "\$PUBLIC_V6_IN_UP" 2>/dev/null | awk '{for(i=1;i<=NF;++i) if (\$i=="dev") { print \$(i+1); exit; }}' || true)
        [ -z "\$PUBLIC_V6_INTERFACE_IN_UP" ] && PUBLIC_V6_INTERFACE_IN_UP=\$(ip -6 addr show | grep "\$PUBLIC_V6_IN_UP" | awk '{print \$NF}' | head -n 1)
        if [ -z "\$PUBLIC_V6_INTERFACE_IN_UP" ]; then
            echo "Warning (wg0_up.sh): Could not determine the public IPv6 interface for NAT. IPv6 masquerading may not work correctly." >&2
        fi
    fi
}
get_public_ips_in_up_script

echo "Debug (wg0_up.sh): PUBLIC_V4_IN_UP = \$PUBLIC_V4_IN_UP"
echo "Debug (wg0_up.sh): PUBLIC_V6_IN_UP = \$PUBLIC_V6_IN_UP"
echo "Debug (wg0_up.sh): PUBLIC_V4_INTERFACE_IN_UP = \$PUBLIC_V4_INTERFACE_IN_UP"
echo "Debug (wg0_up.sh): PUBLIC_V6_INTERFACE_IN_UP = \$PUBLIC_V6_INTERFACE_IN_UP"


# Loop to wait for wg0 interface and its IPv4/IPv6 addresses to be ready
ATTEMPTS=0
MAX_ATTEMPTS=15 # Increased attempts, total wait time 15 * 2 = 30 seconds
SLEEP_INTERVAL=2

WG_LOCAL_V4=""
WG_LOCAL_V6=""

echo "Debug (wg0_up.sh): Waiting for wg0 interface to get IP addresses..."

while [ -z "\$WG_LOCAL_V4" ] && [ \$ATTEMPTS -lt \$MAX_ATTEMPTS ]; do
    WG_LOCAL_V4=\$(ip addr show wg0 | grep "inet\b" | awk '{print \$2}' | cut -d / -f 1 | head -n 1)
    if [ -z "\$WG_LOCAL_V4" ]; then
        echo "Debug (wg0_up.sh): Attempt \$((ATTEMPTS+1))/\$MAX_ATTEMPTS: IPv4 address not ready on wg0. Waiting \$SLEEP_INTERVAL seconds..."
        sleep \$SLEEP_INTERVAL
        ATTEMPTS=\$((ATTEMPTS+1))
    fi
done

if [ -z "\$WG_LOCAL_V4" ]; then
    echo "Error (wg0_up.sh): Failed to get wg0's IPv4 address after multiple attempts. WireGuard might not have started correctly or timed out." >&2
    exit 1
fi

# Only attempt to get WG_LOCAL_V6 if a public IPv6 is detected on the VPS
if [ -n "\$PUBLIC_V6_IN_UP" ]; then
    ATTEMPTS=0 # Reset attempts
    while [ -z "\$WG_LOCAL_V6" ] && [ \$ATTEMPTS -lt \$MAX_ATTEMPTS ]; do
        WG_LOCAL_V6=\$(ip addr show wg0 | grep "inet6\b" | awk '{print \$2}' | cut -d / -f 1 | head -n 1)
        # Ensure a non-link-local address is obtained
        if [[ "\$WG_LOCAL_V6" =~ ^fe80:: ]]; then
            WG_LOCAL_V6="" # Ignore link-local address
        fi

        if [ -z "\$WG_LOCAL_V6" ]; then
            echo "Debug (wg0_up.sh): Attempt \$((ATTEMPTS+1))/\$MAX_ATTEMPTS: IPv6 address not ready on wg0. Waiting \$SLEEP_INTERVAL seconds..."
            sleep \$SLEEP_INTERVAL
            ATTEMPTS=\$((ATTEMPTS+1))
        fi
    done

    if [ -z "\$WG_LOCAL_V6" ]; then
        echo "Warning (wg0_up.sh): Failed to get wg0's IPv6 address after multiple attempts. IPv6 routing via WireGuard may not work." >&2
    fi
else
    echo "Debug (wg0_up.sh): No native public IPv6 detected on VPS, skipping wg0 IPv6 address acquisition."
fi


echo "Debug (wg0_up.sh): Final WG_LOCAL_V4 = \$WG_LOCAL_V4"
echo "Debug (wg0_up.sh): Final WG_LOCAL_V6 = \$WG_LOCAL_V6"


# Define custom routing table 51820
# Ensure only one entry for 51820 wg_custom exists and it's correctly formatted
echo "Debug (wg0_up.sh): Adding/verifying custom routing table 'wg_custom' (51820)..."
if ! grep -qE '^51820\s+wg_custom$' /etc/iproute2/rt_tables; then
    # Remove any existing lines containing '51820' or 'wg_custom' to prevent duplicates/malformed entries
    sed -i '/51820/d; /wg_custom/d' /etc/iproute2/rt_tables 2>/dev/null || true
    echo -e "51820\twg_custom" >> /etc/iproute2/rt_tables # Use tab for consistency
fi


# Clean up potentially existing old rules to ensure idempotency
echo "Debug (wg0_up.sh): Cleaning up old IP rules and routes..."
# Use specific selectors to delete rules to avoid breaking other network configurations.
# Suppress errors if rules don't exist.
[ -n "\$PUBLIC_V4_IN_UP" ] && ip -4 rule del from \$PUBLIC_V4_IN_UP table main pref 100 2>/dev/null || true
[ -n "\$PUBLIC_V6_IN_UP" ] && ip -6 rule del from \$PUBLIC_V6_IN_UP table main pref 100 2>/dev/null || true
[ -n "\$WG_LOCAL_V4" ] && ip -4 rule del from \$WG_LOCAL_V4 table 51820 pref 200 2>/dev/null || true
[ -n "\$WG_LOCAL_V6" ] && ip -6 rule del from \$WG_LOCAL_V6 table 51820 pref 200 2>/dev/null || true
ip rule del pref 300 2>/dev/null || true
ip rule del pref 50 2>/dev/null || true # Cleanup for old script versions that used suppress_prefixlength

ip -4 route flush table 51820 2>/dev/null || true
ip -6 route flush table 51820 2>/dev/null || true

# Clean up potentially existing TCPMSS rules in mangle table
iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
ip6tables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true

# Clean up old FORWARD chain rules (explicitly added by script)
iptables -D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
ip6tables -D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i wg0 -j ACCEPT 2>/dev/null || true
ip6tables -D FORWARD -i wg0 -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -o wg0 -j ACCEPT 2>/dev/null || true
ip6tables -D FORWARD -o wg0 -j ACCEPT 2>/dev/null || true

# Clean up old NAT rules (if they exist)
echo "Debug (wg0_up.sh): Cleaning up old NAT rules..."
[ -n "\$PUBLIC_V4_INTERFACE_IN_UP" ] && iptables -t nat -D POSTROUTING -o \$PUBLIC_V4_INTERFACE_IN_UP -j MASQUERADE 2>/dev/null || true
[ -n "\$PUBLIC_V6_INTERFACE_IN_UP" ] && ip6tables -t nat -D POSTROUTING -o \$PUBLIC_V6_INTERFACE_IN_UP -j MASQUERADE 2>/dev/null || true


echo "Debug (wg0_up.sh): Adding new IP rules and routes..."
# Add new routing rules
# Priority:
# 1. (Highest priority) Ensure traffic from VPS's main public IP (inbound responses) uses the main routing table
[ -n "\$PUBLIC_V4_IN_UP" ] && ip -4 rule add from \$PUBLIC_V4_IN_UP table main pref 100
[ -n "\$PUBLIC_V6_IN_UP" ] && ip -6 rule add from \$PUBLIC_V6_IN_UP table main pref 100

# 2. Route traffic from WireGuard tunnel internal IPs to a custom table
# This ensures that services inside the WireGuard tunnel can egress normally
[ -n "\$WG_LOCAL_V4" ] && ip -4 rule add from \$WG_LOCAL_V4 table 51820 pref 200
# Only add IPv6 rule if WG_LOCAL_V6 was successfully obtained
[ -n "\$WG_LOCAL_V6" ] && ip -6 rule add from \$WG_LOCAL_V6 table 51820 pref 200

# 3. Define the default route for custom table 51820, through the WireGuard interface
# This is the WireGuard egress point
ip -4 route add default dev wg0 table 51820
# Only add IPv6 route if WG_LOCAL_V6 was successfully obtained
[ -n "\$WG_LOCAL_V6" ] && ip -6 route add default dev wg0 table 51820

# 4. (Lowest priority) Fallback rule: all traffic not matched by previous rules is routed to custom table 51820
# This ensures all other outbound traffic, except local inbound responses, goes through WireGuard
ip rule add table 51820 pref 300

# TCP MSS Clamping, performance optimization
echo "Debug (wg0_up.sh): Adding TCP MSS clamping rules..."
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
ip6tables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# --- Configure firewall FORWARD chain rules explicitly (complementing UFW) ---
echo "Debug (wg0_up.sh): Configuring iptables/ip6tables FORWARD chain rules explicitly..."

# Allow established and related connections for both IPv4 and IPv6
iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
ip6tables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Allow traffic from wg0 interface to anywhere
iptables -A FORWARD -i wg0 -j ACCEPT
ip6tables -A FORWARD -i wg0 -j ACCEPT

# Allow traffic from other interfaces to wg0 (e.g., if you have other internal networks that need to use WG)
iptables -A FORWARD -o wg0 -j ACCEPT
ip6tables -A FORWARD -o wg0 -j ACCEPT

# --- Configure firewall NAT chain rules ---
echo "Debug (wg0_up.sh): Configuring iptables/ip6tables NAT chain rules..."

# Set up NAT (Masquerade) for outbound traffic through WireGuard interface
# Masquerade internal IPs from wg0 as the VPS's public IP
[ -n "\$PUBLIC_V4_INTERFACE_IN_UP" ] && iptables -t nat -A POSTROUTING -o \$PUBLIC_V4_INTERFACE_IN_UP -j MASQUERADE
# Ensure PUBLIC_V6_INTERFACE_IN_UP is available for IPv6 NAT
[ -n "\$PUBLIC_V6_INTERFACE_IN_UP" ] && ip6tables -t nat -A POSTROUTING -o \$PUBLIC_V6_INTERFACE_IN_UP -j MASQUERADE


# Additional debug: display current routing tables and rules
echo "Debug (wg0_up.sh): Current IPv4 routing table (main and 51820):"
ip -4 route show table main
ip -4 route show table 51820
echo "Debug (wg0_up.sh): Current IPv6 routing table (main and 51820):"
ip -6 route show table main
ip -6 route show table 51820
echo "Debug (wg0_up.sh): Current IP rules:"
ip rule show
echo "Debug (wg0_up.sh): Current iptables FORWARD chain rules:"
iptables -nvL FORWARD
echo "Debug (wg0_up.sh): Current iptables NAT POSTROUTING chain rules:"
iptables -t nat -nvL POSTROUTING
echo "Debug (wg0_up.sh): Current ip6tables FORWARD chain rules:"
ip6tables -nvL FORWARD
echo "Debug (wg0_up.sh): Current ip6tables NAT POSTROUTING chain rules:"
ip6tables -t nat -nvL POSTROUTING

echo "--- wg0_up.sh Debugging Complete ---"
EOF

  chmod +x /etc/wireguard/wg0_up.sh

  # Create PostDown script (wg0_down.sh)
  cat > /etc/wireguard/wg0_down.sh <<EOF
#!/usr/bin/env bash
# This script cleans up routing rules after the WireGuard interface stops

# Enable debugging. Uncomment the line below for verbose output:
# set -x
set -e # Exit immediately if a command exits with a non-zero status.

echo "--- Debugging wg0_down.sh ---"

# Get server's current public IP and interface
get_public_ips_in_down_script() {
    echo "Debug: Getting public IPs and interfaces for cleanup..."
    PUBLIC_V4_INTERFACE_IN_DOWN=\$(ip -4 route | grep default | awk '{print \$5; exit}' || true)
    PUBLIC_V6_INTERFACE_IN_DOWN=\$(ip -6 route | grep default | awk '{print \$5; exit}' || true)

    PUBLIC_V4_IN_DOWN=\$(ip route get 8.8.8.8 2>/dev/null | awk '{print \$NF; exit}' | grep -Eo '^([0-9]{1,3}\.){3}[0-9]{1,3}\$' || true)
    PUBLIC_V6_IN_DOWN=\$(ip -6 route get 2606:4700:4700::1111 2>/dev/null | awk '{print \$NF; exit}' | grep -Eo '^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}\$' || true)

    [ -z "\$PUBLIC_V4_IN_DOWN" ] && PUBLIC_V4_IN_DOWN=\$(ip -4 addr show | grep 'global' | awk '{print \$2}' | cut -d/ -f1 | head -n 1)
    [ -z "\$PUBLIC_V6_IN_DOWN" ] && PUBLIC_V6_IN_DOWN=\$(ip -6 addr show | grep 'global' | grep -v 'fe80::' | awk '{print \$2}' | cut -d/ -f1 | head -n 1)

    # Now, try to get the interfaces using the identified public IPs (more robust)
    if [ -n "\$PUBLIC_V4_IN_DOWN" ]; then
        PUBLIC_V4_INTERFACE_IN_DOWN=\$(ip route get "\$PUBLIC_V4_IN_DOWN" 2>/dev/null | awk '{for(i=1;i<=NF;++i) if (\$i=="dev") { print \$(i+1); exit; }}' || true)
        [ -z "\$PUBLIC_V4_INTERFACE_IN_DOWN" ] && PUBLIC_V4_INTERFACE_IN_DOWN=\$(ip -4 addr show | grep "\$PUBLIC_V4_IN_DOWN" | awk '{print \$NF}' | head -n 1)
    fi

    if [ -n "\$PUBLIC_V6_IN_DOWN" ]; then
        PUBLIC_V6_INTERFACE_IN_DOWN=\$(ip -6 route get "\$PUBLIC_V6_IN_DOWN" 2>/dev/null | awk '{for(i=1;i<=NF;++i) if (\$i=="dev") { print \$(i+1); exit; }}' || true)
        [ -z "\$PUBLIC_V6_INTERFACE_IN_DOWN" ] && PUBLIC_V6_INTERFACE_IN_DOWN=\$(ip -6 addr show | grep "\$PUBLIC_V6_IN_DOWN" | awk '{print \$NF}' | head -n 1)
    fi
}
get_public_ips_in_down_script

echo "Debug (wg0_down.sh): PUBLIC_V4_INTERFACE_IN_DOWN = \$PUBLIC_V4_INTERFACE_IN_DOWN"
echo "Debug (wg0_down.sh): PUBLIC_V6_INTERFACE_IN_DOWN = \$PUBLIC_V6_INTERFACE_IN_DOWN"
echo "Debug (wg0_down.sh): PUBLIC_V4_IN_DOWN = \$PUBLIC_V4_IN_DOWN"
echo "Debug (wg0_down.sh): PUBLIC_V6_IN_DOWN = \$PUBLIC_V6_IN_DOWN"


# Get WireGuard interface IPs (might be invalid, but attempt to get for old rule cleanup)
WG_LOCAL_V4=\$(ip addr show wg0 | grep "inet\b" | awk '{print \$2}' | cut -d / -f 1 | head -n 1)
# Only attempt to get wg0's local IPv6 address if VPS has native IPv6
[ -n "\$PUBLIC_V6_IN_DOWN" ] && WG_LOCAL_V6=\$(ip addr show wg0 | grep "inet6\b" | awk '{print \$2}' | cut -d / -f 1 | head -n 1)
echo "Debug (wg0_down.sh): WG_LOCAL_V4 (for cleanup) = \$WG_LOCAL_V4"
echo "Debug (wg0_down.sh): WG_LOCAL_V6 (for cleanup) = \$WG_LOCAL_V6"


# Delete custom routing table rules (ensure correct deletion order, inverse of PostUp)
echo "Debug (wg0_down.sh): Deleting TCP MSS clamping rules..."
iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
ip6tables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true

# Clean up NAT rules
echo "Debug (wg0_down.sh): Cleaning up NAT rules..."
[ -n "\$PUBLIC_V4_INTERFACE_IN_DOWN" ] && iptables -t nat -D POSTROUTING -o \$PUBLIC_V4_INTERFACE_IN_DOWN -j MASQUERADE 2>/dev/null || true
[ -n "\$PUBLIC_V6_INTERFACE_IN_DOWN" ] && ip6tables -t nat -D POSTROUTING -o \$PUBLIC_V6_INTERFACE_IN_DOWN -j MASQUERADE 2>/dev/null || true

# Clean up explicit FORWARD chain rules
echo "Debug (wg0_down.sh): Cleaning up explicit FORWARD rules..."
iptables -D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
ip6tables -D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i wg0 -j ACCEPT 2>/dev/null || true
ip6tables -D FORWARD -i wg0 -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -o wg0 -j ACCEPT 2>/dev/null || true
ip6tables -D FORWARD -o wg0 -j ACCEPT 2>/dev/null || true


echo "Debug (wg0_down.sh): Deleting custom IP rules and routes..."
ip rule del pref 300 2>/dev/null || true

ip -4 route flush table 51820 2>/dev/null || true
ip -6 route flush table 51820 2>/dev/null || true

[ -n "\$WG_LOCAL_V4" ] && ip -4 rule del from \$WG_LOCAL_V4 table 51820 pref 200 2>/dev/null || true
[ -n "\$WG_LOCAL_V6" ] && ip -6 rule del from \$WG_LOCAL_V6 table 51820 pref 200 2>/dev/null || true

[ -n "\$PUBLIC_V4_IN_DOWN" ] && ip -4 rule del from \$PUBLIC_V4_IN_DOWN table main pref 100 2>/dev/null || true
[ -n "\$PUBLIC_V6_IN_DOWN" ] && ip -6 rule del from \$PUBLIC_V6_IN_DOWN table main pref 100 2>/dev/null || true

ip rule del pref 50 2>/dev/null || true # Cleanup for old script versions that used incompatible features

# Delete custom routing table name
echo "Debug (wg0_down.sh): Deleting 'wg_custom' (51820) from rt_tables..."
# Remove any existing lines containing '51820' or 'wg_custom' to ensure clean removal
sed -i '/51820/d; /wg_custom/d' /etc/iproute2/rt_tables 2>/dev/null || true

echo "--- wg0_down.sh Debugging Complete ---"
EOF

  chmod +x /etc/wireguard/wg0_down.sh

  info "WireGuard startup/shutdown scripts created: /etc/wireguard/wg0_up.sh and /etc/wireguard/wg0_down.sh"

  # Enable and start WireGuard service with better error reporting
  info "Enabling WireGuard to start on boot..."
  ${SYSTEMCTL_ENABLE[int]} >/dev/null 2>&1 || warning "Failed to enable WireGuard service for boot. It may not start automatically."

  info "Starting WireGuard service... (This may take a moment)"
  # Start the service with verbose output to diagnose PostUp script issues.
  # The redirection to /dev/null is removed to make errors visible.
  if ! ${SYSTEMCTL_START[int]}; then
      echo # Newline for better formatting
      warning "----------------------------------------------------------------"
      warning "WireGuard service failed to start."
      warning "This is often due to an error in the PostUp script."
      info "To diagnose, run the following command and check for errors:"
      hint "  journalctl -u wg-quick@wg0 --no-pager | tail -n 50"
      error "Script aborted. Please review the logs to fix the issue."
  fi

  info "\n--- Custom WireGuard VPN installed successfully! ---"
  get_status
}

# Check custom WireGuard VPN status
get_status() {
  info "\n--- Checking Custom WireGuard VPN Status ---"
  if [ ! -e /etc/wireguard/wg0.conf ]; then
    warning "WireGuard configuration not detected (/etc/wireguard/wg0.conf)."
    return
  fi

  local STATUS=""
  if command -v systemctl >/dev/null 2>&1; then
      STATUS=$(systemctl is-active wg-quick@wg0 2>/dev/null)
  fi

  if [ "$STATUS" = "active" ] || { [ "$SYSTEM" = "Alpine" ] && ip link show wg0 &>/dev/null; }; then
    info "WireGuard service status: Running"
    ip addr show wg0
    echo "-----------------------------------"
    wg show wg0
    echo "-----------------------------------"
    # Use global variables PUBLIC_V4 and PUBLIC_V6 directly
    info "Your VPS's current public IPv4: $PUBLIC_V4"
    if [ -n "$PUBLIC_V6" ]; then
        info "Your VPS's current public IPv6: $PUBLIC_V6"
    else
        warning "Your VPS did not detect a native public IPv6 address. WireGuard IPv6 functionality may be limited."
    fi

    info "Outbound IP via wg0 tunnel (if successful):"
    # Ensure curl uses the wg0 interface for these checks
    curl -s4 --interface wg0 ipinfo.io/ip || echo "  (IPv4 not obtained or not via wg0 tunnel)"

    # Check if wg0 has an IPv6 address before attempting curl -s6
    local WG_HAS_IPV6=$(ip -6 addr show wg0 | grep "inet6\b" | grep -v 'fe80::' | awk '{print $2}' | cut -d/ -f1 | head -n 1)
    if [ -n "$PUBLIC_V6" ]; then # Only attempt to detect IPv6 tunnel if VPS has native IPv6
        if [ -n "$WG_HAS_IPV6" ]; then
            info "  wg0 interface has IPv6: $WG_HAS_IPV6"
            # Add timeout to curl -s6 command to avoid long waits
            curl -s6 --interface wg0 --max-time 10 ipinfo.io/ip || echo "  (IPv6 not obtained via wg0 tunnel. Check routing/firewall.)"
        else
            echo "  (wg0 interface does not have a non-link-local IPv6 address, skipping tunnel IPv6 detection)"
        fi
    else
        echo "  (VPS did not detect native IPv6, skipping tunnel IPv6 detection)"
    fi
    echo "Note: Outbound IP shows the IP through the wg0 tunnel, inbound traffic will still use your native IP."
  else
    warning "WireGuard service status: Not running or an error occurred."
    warning "Please try starting (option 3) or check logs."
  fi
}

# Turn on/off custom WireGuard VPN
toggle_wireguard() {
  info "\n--- Toggling Custom WireGuard VPN ---"
  if [ ! -e /etc/wireguard/wg0.conf ]; then
    warning "WireGuard configuration not detected. Please install first (option 1)."
    return
  fi

  local STATUS=""
  if command -v systemctl >/dev/null 2>&1; then
      STATUS=$(systemctl is-active wg-quick@wg0 2>/dev/null)
  fi

  if [ "$STATUS" = "active" ] || { [ "$SYSTEM" = "Alpine" ] && ip link show wg0 &>/dev/null; }; then
    info "Stopping WireGuard service..."
    # For Alpine, wg-quick down wg0 is sufficient as there's no systemd unit for it directly
    [ "$SYSTEM" = Alpine ] && wg-quick down wg0 >/dev/null 2>&1 || systemctl stop wg-quick@wg0 >/dev/null 2>&1
    info "WireGuard stopped."
  else
    info "Starting WireGuard service..."
    ${SYSTEMCTL_START[int]} >/dev/null 2>&1
    info "WireGuard started."
  fi
  get_status
}

# Uninstall custom WireGuard VPN
uninstall_wireguard() {
  info "\n--- Uninstalling Custom WireGuard VPN ---"
  if [ ! -e /etc/wireguard/wg0.conf ]; then
    warning "WireGuard configuration not detected, no need to uninstall."
    return
  fi

  # Removed 'set -x' by default. Uncomment for debugging:
  # set -x # Enable debugging for uninstall function

  # Attempt to read ENDPOINT from config file for UFW cleanup
  local UNINSTALL_ENDPOINT=""
  if [ -s /etc/wireguard/wg0.conf ]; then
      UNINSTALL_ENDPOINT=$(grep "Endpoint" /etc/wireguard/wg0.conf | awk -F'= ' '{print $2}' | tr -d '[:space:]')
      echo "Debug (uninstall_wireguard): Detected Endpoint from config: $UNINSTALL_ENDPOINT"
  fi

  info "Stopping and disabling WireGuard service..."
  [ "$SYSTEM" = Alpine ] && wg-quick down wg0 >/dev/null 2>&1 || systemctl stop wg-quick@wg0 >/dev/null 2>&1
  [ "$SYSTEM" = Alpine ] && rc-update del local default 2>/dev/null || systemctl disable wg-quick@wg0 >/dev/null 2>&1

  info "Deleting WireGuard configuration files and scripts..."
  rm -f /etc/wireguard/wg0.conf
  rm -f /etc/wireguard/wg0_up.sh
  rm -f /etc/wireguard/wg0_down.sh

  # Delete custom routing table name
  # Remove any existing lines containing '51820' or 'wg_custom' to ensure clean removal
  sed -i '/51820/d; /wg_custom/d' /etc/iproute2/rt_tables 2>/dev/null || true

  # Delete IP forwarding sysctl configuration
  rm -f /etc/sysctl.d/99-wireguard-forwarding.conf
  sysctl --system >/dev/null 2>&1 # Reload all sysctl configurations, removing forwarding rules added by this script

  # Clean up UFW rules
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
      info "Cleaning up UFW rules..."
      # Remove WireGuard interface forwarding rules
      ufw delete allow in on wg0 comment 'Allow WireGuard inbound traffic' 2>/dev/null
      ufw delete allow out on wg0 comment 'Allow WireGuard outbound traffic' 2>/dev/null
      # Remove WireGuard UDP port rule
      local UNINSTALL_ENDPOINT_PORT=""
      if [ -n "$UNINSTALL_ENDPOINT" ]; then
          UNINSTALL_ENDPOINT_PORT=$(echo "$UNINSTALL_ENDPOINT" | awk -F':' '{print $NF}')
          echo "Debug (uninstall_wireguard): Endpoint Port for cleanup: $UNINSTALL_ENDPOINT_PORT"
          ufw delete allow "$UNINSTALL_ENDPOINT_PORT"/udp comment "Allow WireGuard UDP traffic" 2>/dev/null
      else
          warning "Could not get WireGuard port from config file, please manually check UFW rules to ensure port cleanup."
      fi
      
      # Restore UFW forwarding policy (if it was ACCEPT before)
      # Only change back to DROP if currently detected as ACCEPT, to avoid affecting other user configurations
      if grep -q 'DEFAULT_FORWARD_POLICY="ACCEPT"' /etc/default/ufw; then
          sed -i 's/DEFAULT_FORWARD_POLICY="ACCEPT"/DEFAULT_FORWARD_POLICY="DROP"/' /etc/default/ufw
          info "UFW DEFAULT_FORWARD_POLICY attempted to be restored to DROP."
      fi
      ufw reload >/dev/null 2>&1 || warning "UFW reload failed, please check manually."
      info "UFW rules cleaned up. Please manually check DEFAULT_FORWARD_POLICY in /etc/default/ufw."
  fi

  # Attempt to uninstall wireguard-tools dependency (optional, but for cleanup)
  reading "Do you want to uninstall wireguard-tools package? (y/N): " UNINSTALL_DEPS_CONFIRM
  if [[ "${UNINSTALL_DEPS_CONFIRM,,}" = "y" ]]; then
    info "Uninstalling wireguard-tools..."
    ${PACKAGE_UNINSTALL[int]} wireguard-tools >/dev/null 2>&1 || warning "Failed to uninstall wireguard-tools, please check manually."
    # Also uninstall openresolv if it was installed as a dependency
    if command -v apt >/dev/null; then
        sudo apt autoremove --purge openresolv -y >/dev/null 2>&1 || warning "Failed to uninstall openresolv, please check manually."
    elif command -v yum >/dev/null || command -v dnf >/dev/null; then
        sudo yum autoremove openresolv -y >/dev/null 2>&1 || sudo dnf autoremove openresolv -y >/dev/null 2>&1 || warning "Failed to uninstall openresolv, please check manually."
    elif command -v apk >/dev/null; then
        sudo apk del openresolv >/dev/null 2>&1 || warning "Failed to uninstall openresolv, please check manually."
    elif command -v pacman >/dev/null; then
        sudo pacman -Rcnsu openresolv --noconfirm >/dev/null 2>&1 || warning "Failed to uninstall openresolv, please check manually."
    fi
  fi

  info "WireGuard completely uninstalled."
  # Use global variables PUBLIC_V4 and PUBLIC_V6 directly
  info "Your VPS's current public IPv4: $PUBLIC_V4"
  if [ -n "$PUBLIC_V6" ]; then
      info "Your VPS's current public IPv6: $PUBLIC_V6"
  else
      warning "Your VPS did not detect a native public IPv6 address."
  fi
}

# Main menu
menu() {
  clear
  info "--- Custom WireGuard VPN Management Script v$VERSION ---"
  echo ""
  info "Current operating system: $SYS"
  info "Kernel version: $(uname -r)"
  echo ""
  # Ensure PUBLIC_V4 and PUBLIC_V6 are populated by get_public_ips before this
  # Not calling get_status here, directly show public IP, as get_status will check WireGuard status again
  # get_public_ips is already called at the top of menu()
  info "Your VPS's current public IPv4: ${PUBLIC_V4:-'Not detected'}"
  if [ -n "$PUBLIC_V6" ]; then
      info "Your VPS's current public IPv6: $PUBLIC_V6"
  else
      warning "Your VPS did not detect a native public IPv6 address. WireGuard IPv6 functionality may be limited."
  fi
  echo ""
  get_status # Show WireGuard status summary
  echo ""
  info "Please select an operation:"
  info "1. Install Custom WireGuard VPN"
  info "2. Get WireGuard VPN Status"
  info "3. Turn On/Off WireGuard VPN"
  info "4. Uninstall WireGuard VPN"
  info "0. Exit Script"
  reading "\nPlease enter your choice: " CHOICE

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
    4)
      uninstall_wireguard
      ;;
    0)
      info "Exiting script. Goodbye!"
      exit 0
      ;;
    *)
      warning "Invalid choice, please re-enter."
      ;;
  esac
  info "\nPress any key to return to main menu..."
  read -n 1 -s
  menu
}

# --- Script Entry Point ---

check_root
check_operating_system
check_dependencies
get_public_ips # Ensure VPS public IP is obtained at script start
menu
