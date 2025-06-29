#!/bin/bash

# Allow large backlogs on bridges/TAPs
sysctl -w net.core.netdev_max_backlog=250000

# Tune TCP buffers
sysctl -w net.core.rmem_max=16777216 \
           net.core.wmem_max=16777216 \
           net.ipv4.tcp_rmem="4096 87380 16777216" \
           net.ipv4.tcp_wmem="4096 65536 16777216"

# Disable firewalling on bridges if it has the module
cat <<EOF > /etc/sysctl.d/10-disable-firewall-on-bridge.conf
net.bridge.bridge-nf-call-ip6tables = 0
net.bridge.bridge-nf-call-iptables = 0
net.bridge.bridge-nf-call-arptables = 0
EOF

# Check default virtio parameters
qemu-system-x86_64 -device virtio-net-pci,help | grep -E 'mq|vectors|rx_queue_size|tx_queue_size'

# Delete old tap interfaces
for TAP in tap_h1_0 tap_r1_0 tap_r1_1 tap_r1_2 \
           tap_r2_0 tap_r2_1 tap_r3_0 tap_r3_1 \
           tap_r4_0 tap_r4_1 tap_r4_2 tap_h2_0; do
  ip link set dev $TAP down 2>/dev/null || true
  ip tuntap del dev $TAP 2>/dev/null || echo "— $TAP already gone"
done

# Delete old bridge interfaces
for BR in br_h1r1 br_r1r2 br_r1r4 br_r2r3 br_r3r4 br_r4h2; do
  ip link set dev $BR down 2>/dev/null || true
  ip link delete dev $BR type bridge 2>/dev/null && echo "Deleted $BR"
done

# Check for free hugepages
grep -i Huge /proc/meminfo

# Free up some hugepages for our 6 nodes
echo 7168 > /proc/sys/vm/nr_hugepages

# Setup access to all nodes without password
sshpass -p "h1" ssh-copy-id -p 2211 h1@127.0.0.1
sshpass -p "h2" ssh-copy-id -p 2212 h2@127.0.0.1
sshpass -p "r1" ssh-copy-id -p 2221 r1@127.0.0.1
sshpass -p "r2" ssh-copy-id -p 2222 r2@127.0.0.1
sshpass -p "r3" ssh-copy-id -p 2223 r3@127.0.0.1
sshpass -p "r4" ssh-copy-id -p 2224 r4@127.0.0.1
