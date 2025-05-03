#!/bin/bash

ansible-playbook -i inventory setup1.yml

scp -P 2221 seg6-pot-tlv r1@127.0.0.1:/home/r1
scp -P 2222 seg6-pot-tlv r2@127.0.0.1:/home/r2
scp -P 2223 seg6-pot-tlv r3@127.0.0.1:/home/r3
scp -P 2224 seg6-pot-tlv r4@127.0.0.1:/home/r4

ansible-playbook -i inventory setup2.yml
