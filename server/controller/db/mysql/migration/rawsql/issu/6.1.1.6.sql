ALTER TABLE go_genesis_network ADD node_ip CHAR(48) DEFAULT NULL;

UPDATE db_version SET version='6.1.1.6';
