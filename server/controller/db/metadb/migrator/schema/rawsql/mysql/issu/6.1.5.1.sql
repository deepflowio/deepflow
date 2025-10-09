ALTER TABLE analyzer ADD COLUMN pod_name CHAR(64);

UPDATE db_version SET version = '6.1.5.1';
