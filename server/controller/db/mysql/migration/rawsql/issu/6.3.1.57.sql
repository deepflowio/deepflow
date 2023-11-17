ALTER TABLE go_genesis_vinterface ADD COLUMN if_type CHAR(64) DEFAULT '' AFTER device_type;

UPDATE db_version SET version='6.3.1.57';
