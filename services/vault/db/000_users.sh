#!/bin/bash
set -e

echo "Creating application database users..."

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    DO \$\$ BEGIN
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'vault_iam') THEN
            CREATE ROLE vault_iam LOGIN PASSWORD '${VAULT_IAM_DB_PASSWORD}';
        ELSE
            ALTER ROLE vault_iam PASSWORD '${VAULT_IAM_DB_PASSWORD}';
        END IF;
    END \$\$;

    DO \$\$ BEGIN
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'vault_audit') THEN
            CREATE ROLE vault_audit LOGIN PASSWORD '${VAULT_AUDIT_DB_PASSWORD:-changeme}';
        ELSE
            ALTER ROLE vault_audit PASSWORD '${VAULT_AUDIT_DB_PASSWORD:-changeme}';
        END IF;
    END \$\$;
EOSQL

echo "Application database users created."
