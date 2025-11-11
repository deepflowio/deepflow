ALTER TABLE `prometheus_target` ADD COLUMN `epc_id` INTEGER NOT NULL DEFAULT 0 AFTER `other_labels`;

UPDATE db_version SET version='6.4.1.9';
