#!/bin/bash
set -e

echo "GhostWire Client Uninstallation"
echo "================================"

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

read -p "Service name [ghostwire-client]: " GW_SERVICE_NAME
GW_SERVICE_NAME=${GW_SERVICE_NAME:-ghostwire-client}
GW_CONFIG_PATH="/etc/ghostwire/${GW_SERVICE_NAME}.toml"

echo "Stopping and disabling service..."
systemctl stop ${GW_SERVICE_NAME} || true
systemctl disable ${GW_SERVICE_NAME} || true

echo "Removing systemd service..."
rm -f /etc/systemd/system/${GW_SERVICE_NAME}.service
systemctl daemon-reload

echo "Removing binary..."
rm -f /usr/local/bin/ghostwire-client

read -p "Remove configuration files? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -f "${GW_CONFIG_PATH}"
    echo "Configuration removed: ${GW_CONFIG_PATH}"
fi

read -p "Remove ghostwire user? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    userdel ghostwire || true
    echo "User removed"
fi

echo "Uninstallation complete!"
