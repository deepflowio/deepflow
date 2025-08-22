-- modify start, add upgrade sql
ALTER TABLE `alarm_policy`
    ADD COLUMN `monitoring_frequency` CHAR(64) DEFAULT "1m",
    ADD COLUMN `monitoring_interval` CHAR(64) DEFAULT "1m",
    ADD COLUMN `trigger_info_event` INTEGER DEFAULT 0,
    ADD COLUMN `trigger_recovery_event` INTEGER DEFAULT 1;


-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.5.1.12';
-- modify end
