-- modify start, add upgrade sql
ALTER TABLE `pod` ADD COLUMN `pod_service_id` INTEGER DEFAULT 0 AFTER `pod_group_id`;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.5.1.11';
-- modify end
