START TRANSACTION;

-- modify start, add upgrade sql

UPDATE alarm_policy SET user_id=1 WHERE app_type=1;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.3.1.50';
-- modify end

COMMIT;
