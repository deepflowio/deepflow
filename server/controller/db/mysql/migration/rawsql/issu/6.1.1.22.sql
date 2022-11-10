START TRANSACTION;

-- modify start, add upgrade sql

UPDATE vtap SET license_functions="2,3" WHERE process_name="deepflow-agent-ce";

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.1.1.22';
-- modify end

COMMIT;

