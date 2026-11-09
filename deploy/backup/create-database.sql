-- Restore target for `pg_restore` (docs/backup-restore-upgrade.md section 3). Run as the PostgreSQL superuser:
--   psql -U postgres -d postgres -v ON_ERROR_STOP=1 -v dbname=ovlm < deploy/backup/create-database.sql
-- The roles ovlm_owner, ovlm_api and ovlm_worker must exist (docker/postgres/10-ovlm-roles.sh creates them).
-- pg_dump without --create does not carry database-level privileges, and `ovlm migrate` does not re-run the
-- baseline that set them: this file restates them (only the three roles may connect; nothing for PUBLIC).
CREATE DATABASE :"dbname" OWNER ovlm_owner ENCODING 'UTF8' TEMPLATE template0;
REVOKE ALL ON DATABASE :"dbname" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"dbname" TO ovlm_owner, ovlm_api, ovlm_worker;
