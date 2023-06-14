START TRANSACTION;

ALTER TABLE alarm_policy MODIFY COLUMN name CHAR(128) NOT NULL;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.2.1.41';
-- modify end

COMMIT;
