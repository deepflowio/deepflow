-- This template is for upgrade using INSERT/UPDATE/DELETE
-- Tractions are needed for these commands to avoid manual rollback if error occurs.

START TRANSACTION;

-- modify start, add upgrade sql
-- example
UPDATE data_source SET data_table_collection='event.alert_event' where data_table_collection='event.alarm_event';
-- update db_version to latest, remember update DB_VERSION_EXPECTED in migration/version.go
UPDATE db_version SET version='6.6.1.4';
-- modify end

COMMIT;
