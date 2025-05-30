#!/bin/bash

# use ./kdo.sh <PRIV_KEY> <PUB_KEY>

# private key of the sender
PRIV_KEY=$1

# public key of the receiver
PUB_KEY=$2
# Renaud    "0x77bcB19f4B4F3c6077399ADE22C366Bf66F3Ac36"
# Simon     "0x59c75335aAd51b7B705eae13A57f5407139A3A90"

grep -oP 'RPC_.*="(\K[^"]+)' deploy.sh | while read RPC; do
    cast send --rpc-url $RPC --private-key "$PRIV_KEY" $PUB_KEY --value 0.5ether
done
