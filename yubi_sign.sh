#!/bin/bash

PIN="$1"
HASH_HEX="$2"

# convert hex Tx Hash to bytes binary input
echo -n "$HASH_HEX" | xxd -r -p | \
#sign with yubico specify ED25519 key
yubico-piv-tool -a verify-pin --pin "$PIN" --sign -s 9c -A ED25519 -i - | \
#convert back to hex with no CR
xxd -p | tr -d '\n'
