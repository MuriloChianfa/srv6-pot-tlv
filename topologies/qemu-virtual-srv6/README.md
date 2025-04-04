# Setup Instructions

```bash
apt install wget qemu-system ansible sshpass bridge-utils
wget https://cloud-images.ubuntu.com/releases/noble/release-20240423/ubuntu-24.04-server-cloudimg-amd64.img -O base.img
./topology.sh
ansible-playbook -i inventory playbook.yml
```
