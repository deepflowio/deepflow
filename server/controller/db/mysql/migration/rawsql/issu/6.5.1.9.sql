START TRANSACTION;

ALTER TABLE `vm` ADD COLUMN `host_id` INTEGER DEFAULT 0 AFTER launch_server;

-- update db_version to latest
UPDATE db_version SET version='6.5.1.9';

COMMIT;
