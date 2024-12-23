-- This template is for upgrade using INSERT/UPDATE/DELETE
-- Tractions are needed for these commands to avoid manual rollback if error occurs.

START TRANSACTION;

-- modify start, add upgrade sql
-- example
INSERT INTO ch_device (devicetype, deviceid, name, icon_id, team_id, domain_id, sub_domain_id) SELECT 63999, 63999, "Internet", -1, 0, 0, 0 WHERE NOT EXISTS(SELECT * FROM ch_device WHERE devicetype=63999 AND deviceid=63999);
INSERT INTO ch_device (devicetype, deviceid, icon_id, team_id, domain_id, sub_domain_id) SELECT 64000, 64000, -10, 0, 0, 0 WHERE NOT EXISTS(SELECT * FROM ch_device WHERE devicetype=64000 AND deviceid=64000);

-- update db_version to latest, remember update DB_VERSION_EXPECTED in migration/version.go
UPDATE db_version SET version='6.5.1.43';
-- modify end

COMMIT;
