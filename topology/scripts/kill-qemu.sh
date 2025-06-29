#!/bin/bash

pkill -f "qemu-system-x86_64.*"

ssh-keygen -f "/root/.ssh/known_hosts" -R "[127.0.0.1]:2211" 2>/dev/null
ssh-keygen -f "/root/.ssh/known_hosts" -R "[127.0.0.1]:2212" 2>/dev/null

ssh-keygen -f "/root/.ssh/known_hosts" -R "[127.0.0.1]:2221" 2>/dev/null
ssh-keygen -f "/root/.ssh/known_hosts" -R "[127.0.0.1]:2222" 2>/dev/null
ssh-keygen -f "/root/.ssh/known_hosts" -R "[127.0.0.1]:2223" 2>/dev/null
ssh-keygen -f "/root/.ssh/known_hosts" -R "[127.0.0.1]:2224" 2>/dev/null

echo "All QEMU machines was killed successfully."
