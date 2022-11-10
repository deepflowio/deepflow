ALTER TABLE controller ADD COLUMN node_name CHAR(64);

UPDATE db_version SET version = '6.1.1.23';
