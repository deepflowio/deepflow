-- modify start, add upgrade sql
ALTER TABLE `host_device` ADD COLUMN `hostname` CHAR(64) DEFAULT '' AFTER ip;
ALTER TABLE `vm` ADD COLUMN `ip` CHAR(64) DEFAULT ''  AFTER label;
ALTER TABLE `vm` ADD COLUMN `hostname` CHAR(64) DEFAULT '' AFTER ip;
ALTER TABLE `pod_node` ADD COLUMN `hostname` CHAR(64) DEFAULT '' AFTER ip;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.5.1.0';
-- modify end
