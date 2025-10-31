-- This template is for upgrade using INSERT/UPDATE/DELETE
-- Tractions are needed for these commands to avoid manual rollback if error occurs.

START TRANSACTION;

-- modify start, add upgrade sql
-- example
UPDATE vm SET cloud_tags='{}' WHERE cloud_tags IS NULL;

-- update db_version to latest, remember update DB_VERSION_EXPECTED in migration/version.go
UPDATE db_version SET version='6.5.1.44';
-- modify end

COMMIT;
