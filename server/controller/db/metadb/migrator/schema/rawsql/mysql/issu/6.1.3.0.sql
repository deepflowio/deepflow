ALTER TABLE controller ADD COLUMN pod_ip CHAR(64) AFTER node_name;

UPDATE db_version SET version = '6.1.3.0';
