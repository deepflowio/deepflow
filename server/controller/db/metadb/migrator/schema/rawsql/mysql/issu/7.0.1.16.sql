ALTER TABLE `vtap` MODIFY COLUMN `exceptions` BIGINT UNSIGNED DEFAULT 0;

UPDATE db_version SET version='7.0.1.16';
