#!/bin/bash

# Exit on first error
set -e

# Store environment variables for actions
export CDIR="$PWD/.config/softhsm"
export SOFTHSM2_CONF="$CDIR/softhsm2.conf"

# Create directories
mkdir -p "$CDIR"
mkdir -p "$CDIR/tokens"

# Create SoftHSM configuration file
echo "directories.tokendir = $CDIR/tokens" > "$CDIR/softhsm2.conf"
echo "objectstore.backend = file" >> "$CDIR/softhsm2.conf"

# Create SoftHSM token and key
softhsm2-util --init-token --free --label "Testing Token" --pin 1234 --so-pin 1234
openssl genrsa 2048 | openssl pkcs8 -topk8 -nocrypt -out "$CDIR/hsm_key.pem"
softhsm2-util --import "$CDIR/hsm_key.pem" --token "Testing Token" --pin 1234 --label "Testing Key" --id 01

# Create EST client configuration file
cat << EOF > "$PWD/cmd/estclient/testdata/test_hsm.cfg"
{
    "private_key": {
        "hsm": {
            "pkcs11_library_path": "/usr/lib/softhsm/libsofthsm2.so",
            "token_label": "Testing Token",
            "token_pin": "1234",
            "key_id": 1
        }
    }
}
EOF

cat "$PWD/cmd/estclient/testdata/test_hsm.cfg"
