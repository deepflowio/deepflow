-- modify start, add upgrade sql
ALTER TABLE `vtap` ADD COLUMN `raw_hostname` VARCHAR(256)  AFTER name;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.5.1.3';
-- modify end
