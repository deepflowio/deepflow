ALTER TABLE go_genesis_vpc ADD vtap_id INTEGER DEFAULT NULL;

UPDATE db_version SET version='6.1.1.17';
