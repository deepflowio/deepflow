ALTER TABLE `vinterface` ADD COLUMN `vmac` CHAR(32) DEFAULT '' AFTER `mac`;
UPDATE db_version SET version='6.1.8.18';
