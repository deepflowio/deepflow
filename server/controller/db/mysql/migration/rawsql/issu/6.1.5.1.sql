USE deepflow;

ALTER TABLE analyzer ADD COLUMN pod_name;

UPDATE db_version SET version = '6.1.5.1';
