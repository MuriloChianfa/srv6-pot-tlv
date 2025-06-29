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
./scripts/topology.sh

# ! Wait until all nodes are successfully booted

# Run the Ansible playbook to prepare the environment
ansible-playbook -i inventory scripts/ansible/prepare.yml

# Run the Ansible playbook to setup the if addresses and SRv6 domain
ansible-playbook -i inventory scripts/ansible/topology.yml

# Compile all srv6-pot-tlv algorithms
make all

# Copy all algorithms to the remote server
./topology/scripts/copy.sh

# Install and configure one algorithm
./topology/scripts/setup.sh blake3
```
