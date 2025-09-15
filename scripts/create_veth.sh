#!/bin/bash

# Script to create a dummy interface with IP 172.16.0.1/24
set -e

INTERFACE="dummy0"
IP_ADDRESS="172.16.0.1"
NETMASK="/24"

echo "Creating dummy interface $INTERFACE with IP $IP_ADDRESS$NETMASK..."

# Load dummy kernel module if not loaded
sudo modprobe dummy

# Check if interface already exists
if ip link show $INTERFACE >/dev/null 2>&1; then
    echo "Interface $INTERFACE already exists. Removing IP address..."
    sudo ip addr flush dev $INTERFACE
else
    # Create dummy interface
    echo "Creating dummy interface $INTERFACE"
    sudo ip link add $INTERFACE type dummy
fi

# Assign IP address
echo "Assigning IP address $IP_ADDRESS$NETMASK to $INTERFACE"
sudo ip addr add $IP_ADDRESS$NETMASK dev $INTERFACE

# Bring interface up
echo "Bringing interface up..."
sudo ip link set $INTERFACE up

# Show interface configuration
echo ""
echo "Interface created successfully!"
echo "Interface status:"
ip addr show $INTERFACE