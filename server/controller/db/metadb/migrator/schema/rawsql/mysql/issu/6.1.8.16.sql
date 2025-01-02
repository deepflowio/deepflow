-- 为了和 v6.1 版本对齐，6.1.8.14.sql 和 6.1.8.15.sql 在 v6.2 版本忽略
ALTER TABLE pod_service ADD COLUMN label TEXT COMMENT 'separated by ,';

UPDATE db_version SET version = '6.1.8.16';
