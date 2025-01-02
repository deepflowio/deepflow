ALTER TABLE kubernetes_cluster ADD COLUMN updated_time DATETIME DEFAULT NULL AFTER `value`;

UPDATE db_version SET version='6.3.1.14';
