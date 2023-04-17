START TRANSACTION;

-- modify start, add upgrade sql

ALTER TABLE `report` ADD INDEX index_name (`lcuuid`);

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.2.1.34';
-- modify end

COMMIT;
