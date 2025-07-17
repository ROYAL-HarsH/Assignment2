#!/usr/bin/env bash
# assignment2.sh
# Idempotent configuration script for server1
# Ensures static IP, hosts file, services, and user accounts

set -euo pipefail
IFS=$'\n\t'

# Colors for output
GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
RESET="\e[0m"

# Log functions
info() { echo -e "${GREEN}[INFO]${RESET} $*"; }
warn() { echo -e "${YELLOW}[WARN]${RESET} $*"; }
error() { echo -e "${RED}[ERROR]${RESET} $*" >&2; }

# Check if running as root
if [[ $EUID -ne 0 ]]; then
  error "This script must be run as root. Exiting."
  exit 1
fi

# 1. Configure netplan for static IP on eth1 (mgmt network is eth0)
info "Configuring netplan for static IP..."
NETPLAN_FILE="/etc/netplan/00-installer-config.yaml"
INTERFACE="eth1"
STATIC_IP="192.168.16.21/24"
GATEWAY="192.168.16.2"
DNS_SERVERS=("8.8.8.8" "8.8.4.4")

if grep -q "address: $STATIC_IP" "$NETPLAN_FILE"; then
  info "Netplan already configured for $STATIC_IP on $INTERFACE"
else
  info "Updating netplan file: $NETPLAN_FILE"
  backup="${NETPLAN_FILE}.bak.$(date +%s)"
  cp "$NETPLAN_FILE" "$backup"
  info "Backup saved as $backup"
  # Remove existing config under INTERFACE
  yq eval "del(.network.ethernets.${INTERFACE})" -i "$NETPLAN_FILE"
  # Add static config
  yq eval ".network.ethernets.${INTERFACE} = {dhcp4: false, addresses: ['$STATIC_IP'], gateway4: '${GATEWAY}', nameservers: {addresses: ${DNS_SERVERS}}}" -i "$NETPLAN_FILE"
  netplan apply
  info "Applied netplan configuration."
fi

# 2. Ensure /etc/hosts entry for server1
info "Updating /etc/hosts..."
HOSTS_LINE="$STATIC_IP server1"
if grep -qE "^${STATIC_IP}\s+server1" /etc/hosts; then
  info "/etc/hosts already contains '$HOSTS_LINE'"
else
  # Remove any old entry for server1
  sed -i "/server1/d" /etc/hosts
  echo "$HOSTS_LINE" >> /etc/hosts
  info "Added '$HOSTS_LINE' to /etc/hosts"
fi

# 3. Install required packages apache2 and squid
PACKAGES=(apache2 squid)
info "Installing required packages: ${PACKAGES[*]}"
for pkg in "${PACKAGES[@]}"; do
  if dpkg -l | grep -q "^ii  $pkg "; then
    info "$pkg is already installed"
  else
    info "Installing $pkg"
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg"
  fi
done

# 4. Create user accounts
info "Creating user accounts..."
USERS=(dennis aubrey captain snibbles brownie scooter sandy perrier cindy tiger yoda)
SSH_KEY_ED25519="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG4rT3vTt99Ox5kndS4HmgTrKBT8SKzhK4rhGkEVGlCI student@generic-vm"

for user in "${USERS[@]}"; do
  if id "$user" &>/dev/null; then
    info "User $user exists"
  else
    info "Creating user $user"
    useradd -m -s /bin/bash "$user"
  fi

  # Add to sudo group if dennis
  if [[ $user == "dennis" ]]; then
    usermod -aG sudo dennis
    info "Granted sudo to dennis"
  fi

  # Setup SSH keys
  USER_HOME="/home/$user"
  SSH_DIR="$USER_HOME/.ssh"
  AUTH_KEYS="$SSH_DIR/authorized_keys"

  mkdir -p "$SSH_DIR"
  touch "$AUTH_KEYS"
  chmod 700 "$SSH_DIR"
  chmod 600 "$AUTH_KEYS"
  chown -R "$user":"$user" "$SSH_DIR"

  # Add provided ed25519 key for dennis
  if [[ $user == "dennis" ]]; then
    if ! grep -qxF "$SSH_KEY_ED25519" "$AUTH_KEYS"; then
      echo "$SSH_KEY_ED25519" >> "$AUTH_KEYS"
      info "Added provided ed25519 key to dennis"
    else
      info "Provided ed25519 key already present for dennis"
    fi
  fi

  # Generate RSA and ed25519 for other users if not exist
  if [[ $user != "dennis" ]]; then
    su - "$user" -c "/usr/bin/ssh-keygen -t rsa -b 4096 -N '' -f $SSH_DIR/id_rsa <<< y 2>/dev/null || true"
    su - "$user" -c "/usr/bin/ssh-keygen -t ed25519 -N '' -f $SSH_DIR/id_ed25519 <<< y 2>/dev/null || true"
    # Add public keys to authorized_keys
    for pub in "$SSH_DIR"/*.pub; do
      if ! grep -qxF "$(cat $pub)" "$AUTH_KEYS"; then
        cat "$pub" >> "$AUTH_KEYS"
      fi
    done
    info "Generated and installed keys for $user"
  fi

done

info "Assignment2 configuration complete!"
