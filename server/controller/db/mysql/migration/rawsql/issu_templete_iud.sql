-- This templete is for upgrade using INSERT/UPDATE/DELETE
START TRANSACTION;

-- modify start, add upgrade sql
-- example
INSERT INTO epc (name) VALUE ("example");
-- update db_version to latest, remeber update DB_VERSION_EXPECTED in migration/version.go
UPDATE db_version SET version='6.1.1.0';
-- modify end

COMMIT;
