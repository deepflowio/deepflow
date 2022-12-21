ALTER TABLE vm ADD COLUMN cloud_tags TEXT COMMENT 'separated by ,' AFTER launch_server;

UPDATE db_version SET version='6.2.1.2';
