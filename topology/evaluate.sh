#!/bin/bash

ansible-playbook -i inventory setup1.yml
ssh -p 2211 h1@127.0.0.1 "python3 collect-round-trip-time.py baseline"
ssh -p 2211 h1@127.0.0.1 "python3 collect-throughput.py baseline"

./setup.sh blake3
ssh -p 2211 h1@127.0.0.1 "python3 collect-round-trip-time.py blake3"
ssh -p 2211 h1@127.0.0.1 "python3 collect-throughput.py blake3"

./setup.sh siphash
ssh -p 2211 h1@127.0.0.1 "python3 collect-round-trip-time.py siphash"
ssh -p 2211 h1@127.0.0.1 "python3 collect-throughput.py siphash"

./setup.sh halfsiphash
ssh -p 2211 h1@127.0.0.1 "python3 collect-round-trip-time.py halfsiphash"
ssh -p 2211 h1@127.0.0.1 "python3 collect-throughput.py halfsiphash"

./setup.sh poly1305
ssh -p 2211 h1@127.0.0.1 "python3 collect-round-trip-time.py poly1305"
ssh -p 2211 h1@127.0.0.1 "python3 collect-throughput.py poly1305"

ssh -p 2211 h1@127.0.0.1 "mkdir -p rtt_data/"
ssh -p 2211 h1@127.0.0.1 "mkdir -p throughput_data/"
ssh -p 2211 h1@127.0.0.1 "rm rtt_data/*"
ssh -p 2211 h1@127.0.0.1 "rm throughput_data/*"
ssh -p 2211 h1@127.0.0.1 "mv rtt_data_* rtt_data/"
ssh -p 2211 h1@127.0.0.1 "mv throughput_data_* throughput_data/"
ssh -p 2211 h1@127.0.0.1 "zip -r rtt_data.zip rtt_data/"
ssh -p 2211 h1@127.0.0.1 "zip -r throughput_data.zip throughput_data/"

scp -P 2211 h1@127.0.0.1:/home/h1/rtt_data.zip .
scp -P 2211 h1@127.0.0.1:/home/h1/throughput_data.zip .
