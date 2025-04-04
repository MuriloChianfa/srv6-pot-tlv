#!/bin/bash
set -uo pipefail

# This script sets up a virtual SRv6 network infrastructure using QEMU.
# It creates the required bridges and TAP devices, then launches six VMs:
#   - 4 Routers: r1, r2, r3, r4
#   - 2 Hosts: h1, h2
#
# Topology:
#
#           r2 --- r3
#            |       |
# h1 -- r1 --- r4 --- h2
#
# Ensure you run this script as root.

# -------------------------
# Bridge Definitions
# -------------------------
BR_H1_R1="br_h1r1"
BR_R1_R2="br_r1r2"
BR_R1_R4="br_r1r4"
BR_R2_R3="br_r2r3"
BR_R3_R4="br_r3r4"
BR_R4_H2="br_r4h2"

# Function to create a bridge if it doesn't exist
create_bridge() {
    local BR=$1
    if ! ip link show "$BR" &>/dev/null; then
        ip link add name "$BR" type bridge
        ip link set "$BR" up
        echo "Bridge $BR created."
    else
        echo "Bridge $BR already exists."
    fi
}

# Create the required bridges
create_bridge "$BR_H1_R1"
create_bridge "$BR_R1_R2"
create_bridge "$BR_R1_R4"
create_bridge "$BR_R2_R3"
create_bridge "$BR_R3_R4"
create_bridge "$BR_R4_H2"

# -------------------------
# TAP Device Creation
# -------------------------
# Function to create a TAP device and attach it to a bridge
create_tap() {
    local TAP=$1
    local BR=$2
    if ! ip link show "$TAP" &>/dev/null; then
        ip tuntap add dev "$TAP" mode tap
        ip link set "$TAP" up
        ip link set "$TAP" master "$BR"
        echo "Tap $TAP created and attached to bridge $BR."
    else
        echo "Tap $TAP already exists."
    fi
}

# h1: 1 interface (br_h1r1)
create_tap "tap_h1_0" "$BR_H1_R1"

# r1: 3 interfaces (br_h1r1, br_r1r2, br_r1r4)
create_tap "tap_r1_0" "$BR_H1_R1"
create_tap "tap_r1_1" "$BR_R1_R2"
create_tap "tap_r1_2" "$BR_R1_R4"

# r2: 2 interfaces (br_r1r2, br_r2r3)
create_tap "tap_r2_0" "$BR_R1_R2"
create_tap "tap_r2_1" "$BR_R2_R3"

# r3: 2 interfaces (br_r2r3, br_r3r4)
create_tap "tap_r3_0" "$BR_R2_R3"
create_tap "tap_r3_1" "$BR_R3_R4"

# r4: 3 interfaces (br_r1r4, br_r3r4, br_r4h2)
create_tap "tap_r4_0" "$BR_R1_R4"
create_tap "tap_r4_1" "$BR_R3_R4"
create_tap "tap_r4_2" "$BR_R4_H2"

# h2: 1 interface (br_r4h2)
create_tap "tap_h2_0" "$BR_R4_H2"

# -------------------------
# VM Image Preparation
# -------------------------
# Assume a base image "base.img" exists.
BASE_IMG="base.img"
prepare_vm_image() {
    local VM_NAME=$1
    local IMG_FILE="${VM_NAME}.img"
    if [ ! -f "$IMG_FILE" ]; then
        cp "$BASE_IMG" "${VM_NAME}/$IMG_FILE"
        echo "Created disk image for $VM_NAME."
    	cloud-localds "${VM_NAME}/seed-${VM_NAME}.img" "${VM_NAME}/user-data" "${VM_NAME}/meta-data"
	echo "Created cloud-init seed img for $VM_NAME."
    else
        echo "Disk image for $VM_NAME already exists."
    fi
}

prepare_vm_image "h1"
prepare_vm_image "r1"
prepare_vm_image "r2"
prepare_vm_image "r3"
prepare_vm_image "r4"
prepare_vm_image "h2"

# -------------------------
# Launching VMs with QEMU
# -------------------------
# Function to launch a VM with given QEMU network options.
launch_vm() {
    local VM_NAME=$1
    local VM_PORT=$2
    local IMG_FILE="${VM_NAME}/${VM_NAME}.img"
    shift
    shift
    nohup qemu-system-x86_64 -enable-kvm -nographic -m 2048 -smp 4 -name "$VM_NAME" -hda "$IMG_FILE" \
	    -netdev user,id=net0,hostfwd="tcp::${VM_PORT}-:22" -device virtio-net-pci,netdev=net0 \
	    -drive file="${VM_NAME}/seed-${VM_NAME}.img",if=virtio,index=1 "$@" > "${VM_NAME}/qemu.log" 2>&1 &
    echo "Launched VM $VM_NAME."
}

# Launch h1: one NIC on tap_h1_0
launch_vm "h1" "2211" \
    -netdev tap,id=net1,ifname=tap_h1_0 \
    -device virtio-net-pci,netdev=net1,mac=52:54:00:00:01:01

# Launch r1: three NICs (tap_r1_0, tap_r1_1, tap_r1_2)
launch_vm "r1" "2221" \
    -netdev tap,id=net1,ifname=tap_r1_0 \
    -device virtio-net-pci,netdev=net1,mac=52:54:00:00:02:01 \
    -netdev tap,id=net2,ifname=tap_r1_1 \
    -device virtio-net-pci,netdev=net2,mac=52:54:00:00:02:02 \
    -netdev tap,id=net3,ifname=tap_r1_2 \
    -device virtio-net-pci,netdev=net3,mac=52:54:00:00:02:03

# Launch r2: two NICs (tap_r2_0, tap_r2_1)
launch_vm "r2" "2222" \
    -netdev tap,id=net1,ifname=tap_r2_0 \
    -device virtio-net-pci,netdev=net1,mac=52:54:00:00:03:01 \
    -netdev tap,id=net2,ifname=tap_r2_1 \
    -device virtio-net-pci,netdev=net2,mac=52:54:00:00:03:02

# Launch r3: two NICs (tap_r3_0, tap_r3_1)
launch_vm "r3" "2223" \
    -netdev tap,id=net1,ifname=tap_r3_0 \
    -device virtio-net-pci,netdev=net1,mac=52:54:00:00:04:01 \
    -netdev tap,id=net2,ifname=tap_r3_1 \
    -device virtio-net-pci,netdev=net2,mac=52:54:00:00:04:02

# Launch r4: three NICs (tap_r4_0, tap_r4_1, tap_r4_2)
launch_vm "r4" "2224" \
    -netdev tap,id=net1,ifname=tap_r4_0 \
    -device virtio-net-pci,netdev=net1,mac=52:54:00:00:05:01 \
    -netdev tap,id=net2,ifname=tap_r4_1 \
    -device virtio-net-pci,netdev=net2,mac=52:54:00:00:05:02 \
    -netdev tap,id=net3,ifname=tap_r4_2 \
    -device virtio-net-pci,netdev=net3,mac=52:54:00:00:05:03

# Launch h2: one NIC on tap_h2_0
launch_vm "h2" "2212" \
    -netdev tap,id=net1,ifname=tap_h2_0 \
    -device virtio-net-pci,netdev=net1,mac=52:54:00:00:06:01

echo "All VMs have been launched successfully."


