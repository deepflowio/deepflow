
ALTER TABLE pod ADD COLUMN annotation TEXT COMMENT 'separated by ,' AFTER label;
ALTER TABLE pod ADD COLUMN env TEXT COMMENT 'separated by ,' AFTER annotation;

ALTER TABLE pod_service ADD COLUMN annotation TEXT COMMENT 'separated by ,' AFTER label;

UPDATE db_version SET version='6.3.1.0';
