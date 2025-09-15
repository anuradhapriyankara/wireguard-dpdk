#!/bin/bash

# Script to destroy the veth or dummy interface
set -e

# INTERFACE="veth0"
DUMMY_INTERFACE="dummy0"

echo "Cleaning up network interfaces..."

# Remove veth interface if it exists
# if ip link show $INTERFACE >/dev/null 2>&1; then
#     echo "Removing veth interface $INTERFACE..."
#     sudo ip addr flush dev $INTERFACE 2>/dev/null || true
#     sudo ip link set $INTERFACE down 2>/dev/null || true
#     sudo ip link del $INTERFACE 2>/dev/null || true
#     echo "Veth interface $INTERFACE removed."
# fi

# Remove dummy interface if it exists
if ip link show $DUMMY_INTERFACE >/dev/null 2>&1; then
    echo "Removing dummy interface $DUMMY_INTERFACE..."
    sudo ip addr flush dev $DUMMY_INTERFACE 2>/dev/null || true
    sudo ip link set $DUMMY_INTERFACE down 2>/dev/null || true
    sudo ip link del $DUMMY_INTERFACE 2>/dev/null || true
    echo "Dummy interface $DUMMY_INTERFACE removed."
fi

echo "Cleanup completed!"