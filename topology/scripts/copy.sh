#!/bin/bash

scp ./cmd/build/seg6-pot-tlv-blake3 root@192.168.0.57:/root/qemu-virtual-srv6/
scp ./cmd/build/seg6-pot-tlv-poly1305 root@192.168.0.57:/root/qemu-virtual-srv6/
scp ./cmd/build/seg6-pot-tlv-siphash root@192.168.0.57:/root/qemu-virtual-srv6/
scp ./cmd/build/seg6-pot-tlv-halfsiphash root@192.168.0.57:/root/qemu-virtual-srv6/
scp ./cmd/build/seg6-pot-tlv-hmac-sha1 root@192.168.0.57:/root/qemu-virtual-srv6/
scp ./cmd/build/seg6-pot-tlv-hmac-sha256 root@192.168.0.57:/root/qemu-virtual-srv6/
