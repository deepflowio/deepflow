ALTER TABLE ch_ip_resource ADD COLUMN uid CHAR(64);
ALTER TABLE ch_ip_resource CHANGE vpc_id l3_epc_id INTEGER;
ALTER TABLE ch_ip_resource CHANGE vpc_name l3_epc_name VARCHAR(256);

UPDATE db_version SET version = '6.1.6.0';
