#!/bin/bash

ansible-playbook -i inventory setup1.yml
ssh -p 2211 h1@127.0.0.1 "python3 collect-round-trip-time.py baseline"

./setup.sh blake3
ssh -p 2211 h1@127.0.0.1 "python3 collect-round-trip-time.py blake3"

./setup.sh siphash
ssh -p 2211 h1@127.0.0.1 "python3 collect-round-trip-time.py siphash"

./setup.sh halfsiphash
ssh -p 2211 h1@127.0.0.1 "python3 collect-round-trip-time.py halfsiphash"

./setup.sh poly1305
ssh -p 2211 h1@127.0.0.1 "python3 collect-round-trip-time.py poly1305"

ssh -p 2211 h1@127.0.0.1 "rm rtt_data/*"
ssh -p 2211 h1@127.0.0.1 "mv rtt_data_* rtt_data/"
ssh -p 2211 h1@127.0.0.1 "zip -r rtt_data.zip rtt_data/"

scp -P 2211 h1@127.0.0.1:/home/h1/rtt_data.zip .
