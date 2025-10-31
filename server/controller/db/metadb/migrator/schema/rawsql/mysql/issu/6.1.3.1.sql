ALTER TABLE analyzer ADD COLUMN pod_ip CHAR(64) AFTER nat_ip_enabled;

UPDATE db_version SET version = '6.1.3.1';
