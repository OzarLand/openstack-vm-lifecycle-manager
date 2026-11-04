#!/bin/sh
# Runs once, as the Postgres superuser, on first start of an empty data directory.
# Creates the three OVLM roles (passwords from secret files, never from env) and the database.
# `ovlm_owner` is not a superuser: it may create roles (the baseline migration is idempotent about them).
set -eu

read_secret() { tr -d '\r\n' < "$1"; }

OWNER_PW=$(read_secret /run/secrets/db_owner_password)
API_PW=$(read_secret /run/secrets/db_api_password)
WORKER_PW=$(read_secret /run/secrets/db_worker_password)

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -v owner_pw="$OWNER_PW" -v api_pw="$API_PW" -v worker_pw="$WORKER_PW" <<'SQL'
CREATE ROLE ovlm_owner  LOGIN CREATEROLE NOSUPERUSER NOCREATEDB NOREPLICATION NOBYPASSRLS PASSWORD :'owner_pw';
CREATE ROLE ovlm_api    LOGIN NOSUPERUSER NOCREATEDB NOREPLICATION NOBYPASSRLS PASSWORD :'api_pw';
CREATE ROLE ovlm_worker LOGIN NOSUPERUSER NOCREATEDB NOREPLICATION NOBYPASSRLS PASSWORD :'worker_pw';
CREATE DATABASE ovlm OWNER ovlm_owner;
SQL
