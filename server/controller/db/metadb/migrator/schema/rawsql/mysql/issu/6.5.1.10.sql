-- modify start, add upgrade sql
ALTER TABLE `ch_chost` 
    ADD COLUMN `ip` CHAR(64),
    ADD COLUMN `hostname` VARCHAR(256);

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.5.1.10';
-- modify end
