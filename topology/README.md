# QEMU SRv6 LAB

<div align="center"><img src="./qemu-virtual-srv6.png" /></div>

# Setup Instructions

Fresh installation of Debian 12:

```bash
# Install all dependencies to run the topology
apt install wget qemu-system ansible sshpass bridge-utils

# Download the ubuntu image
wget https://cloud-images.ubuntu.com/releases/noble/release-20240423/ubuntu-24.04-server-cloudimg-amd64.img -O base.img

# Run the script to create and start the topology
./topology.sh

# ! Wait until all nodes are successfully booted

# Run the Ansible playbook to setup the if addresses and SRv6 domain
ansible-playbook -i inventory playbook.yml

# Shutdown all VMs
./kill-qemu.sh

# Resize all routers images
qemu-img resize r1/r1.img +10G
qemu-img resize r2/r2.img +10G
qemu-img resize r3/r3.img +10G
qemu-img resize r4/r4.img +10G
```

## For each router

```bash
# Install packages for bpftool in each router
apt install linux-image-$(uname -r) linux-headers-$(uname -r) linux-tools-$(uname -r)
```
