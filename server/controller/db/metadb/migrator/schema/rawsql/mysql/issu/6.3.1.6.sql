ALTER TABLE pod ADD COLUMN container_ids TEXT COMMENT 'separated by ,' AFTER env;
ALTER TABLE process ADD COLUMN container_id CHAR(64) DEFAULT "" AFTER lcuuid;
ALTER TABLE go_genesis_process ADD COLUMN container_id CHAR(64) DEFAULT "" AFTER user;

UPDATE db_version SET version='6.3.1.6';
