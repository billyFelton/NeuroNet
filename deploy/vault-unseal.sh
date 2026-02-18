#!/bin/bash
# vault-unseal.sh — Auto-unseal Vault for development/testing
# Place unseal keys in ~/git/NeuroNet/deploy/.env as:
#   VAULT_UNSEAL_KEY_1=...
#   VAULT_UNSEAL_KEY_2=...
#   VAULT_UNSEAL_KEY_3=...

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/.env" 2>/dev/null || true

if [ -z "$VAULT_UNSEAL_KEY_1" ] || [ -z "$VAULT_UNSEAL_KEY_2" ] || [ -z "$VAULT_UNSEAL_KEY_3" ]; then
    echo "ERROR: Set VAULT_UNSEAL_KEY_1, _2, _3 in .env"
    exit 1
fi

echo "Waiting for Vault to start..."
for i in $(seq 1 30); do
    if docker exec neuro-hcvault vault status 2>/dev/null | grep -q "Sealed"; then
        break
    fi
    sleep 1
done

SEALED=$(docker exec neuro-hcvault vault status -format=json 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['sealed'])" 2>/dev/null || echo "true")

if [ "$SEALED" = "True" ] || [ "$SEALED" = "true" ]; then
    echo "Unsealing Vault..."
    docker exec neuro-hcvault vault operator unseal "$VAULT_UNSEAL_KEY_1"
    docker exec neuro-hcvault vault operator unseal "$VAULT_UNSEAL_KEY_2"
    docker exec neuro-hcvault vault operator unseal "$VAULT_UNSEAL_KEY_3"
    echo "Vault unsealed successfully."
else
    echo "Vault is already unsealed."
fi
