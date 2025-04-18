#!/bin/bash
set -euo pipefail

ps aux | grep -v "grep" | grep "qemu-system" | awk '{print $2}' | xargs kill

ssh-keygen -f "/root/.ssh/known_hosts" -R "[127.0.0.1]:2211"
ssh-keygen -f "/root/.ssh/known_hosts" -R "[127.0.0.1]:2212"

ssh-keygen -f "/root/.ssh/known_hosts" -R "[127.0.0.1]:2221"
ssh-keygen -f "/root/.ssh/known_hosts" -R "[127.0.0.1]:2222"
ssh-keygen -f "/root/.ssh/known_hosts" -R "[127.0.0.1]:2223"
ssh-keygen -f "/root/.ssh/known_hosts" -R "[127.0.0.1]:2224"
