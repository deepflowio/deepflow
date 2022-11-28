
ALTER TABLE ch_ip_resource CHANGE l3_epc_id vpc_id INTEGER;
ALTER TABLE ch_ip_resource CHANGE l3_epc_name vpc_name VARCHAR(256);

UPDATE db_version SET version = '6.1.6.2';