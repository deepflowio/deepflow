-- This template is for upgrade using INSERT/UPDATE/DELETE
-- Tractions are needed for these commands to avoid manual rollback if error occurs.

START TRANSACTION;

-- modify start, add upgrade sql
-- example
DELETE FROM alarm_policy WHERE name="采集器所在系统空闲内存低";
-- update db_version to latest, remember update DB_VERSION_EXPECTED in migration/version.go
UPDATE db_version SET version='6.6.1.3';
-- modify end

COMMIT;