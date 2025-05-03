#!/bin/bash

# Check if an argument is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <algorithm>"
  echo "Available algorithms: blake3, siphash, poly1305"
  exit 1
fi

ALGO=$1
ALLOWED_ALGOS=("blake3" "siphash" "poly1305")

# Validate the argument
if [[ ! " ${ALLOWED_ALGOS[@]} " =~ " ${ALGO} " ]]; then
    echo "Error: Invalid algorithm '$ALGO'."
    echo "Available algorithms: blake3, siphash, poly1305"
    exit 1
fi

# Construct the filename based on the algorithm
SOURCE_FILE="seg6-pot-tlv-${ALGO}"
DEST_FILE="seg6-pot-tlv" # Keep the destination filename simple

# Check if the source file exists
if [ ! -f "${SOURCE_FILE}" ]; then
    echo "Error: Source file '${SOURCE_FILE}' not found."
    echo "Make sure you have compiled the ${ALGO} version using 'make ${ALGO}'."
    exit 1
fi

echo "Using algorithm: ${ALGO}"
echo "Copying file: ${SOURCE_FILE}"

cp ${SOURCE_FILE} seg6-pot-tlv

ansible-playbook -i inventory setup1.yml

scp -P 2221 seg6-pot-tlv r1@127.0.0.1:/home/r1
scp -P 2222 seg6-pot-tlv r2@127.0.0.1:/home/r2
scp -P 2223 seg6-pot-tlv r3@127.0.0.1:/home/r3
scp -P 2224 seg6-pot-tlv r4@127.0.0.1:/home/r4

ansible-playbook -i inventory setup2.yml
