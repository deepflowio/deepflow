ALTER TABLE pod_namespace ADD COLUMN cloud_tags TEXT COMMENT 'separated by ,' AFTER alias;

UPDATE db_version SET version='6.2.1.3';
