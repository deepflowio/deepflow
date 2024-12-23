ALTER TABLE `ch_gprocess` ADD COLUMN `vpc_id` INTEGER;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/version.go
UPDATE db_version SET version='6.4.1.19';
-- modify end
