
ALTER TABLE `process` ADD COLUMN `epc_id` INTEGER DEFAULT 0;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/version.go
UPDATE db_version SET version='6.4.1.18';
-- modify end
