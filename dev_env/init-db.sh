#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    CREATE USER ownca WITH PASSWORD 'ownca';
    CREATE DATABASE ownca OWNER ownca;
    GRANT ALL PRIVILEGES ON DATABASE ownca TO ownca;
EOSQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" -d ownca <<-EOSQL
    GRANT ALL ON SCHEMA public TO ownca;
EOSQL
