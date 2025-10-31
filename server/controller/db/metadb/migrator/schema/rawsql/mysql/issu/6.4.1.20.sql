
ALTER TABLE ch_ip_resource CHANGE vpc_id l3_epc_id INTEGER;
ALTER TABLE ch_ip_resource CHANGE vpc_name l3_epc_name VARCHAR(256);
ALTER TABLE ch_gprocess CHANGE vpc_id l3_epc_id INTEGER;
ALTER TABLE ch_chost CHANGE vpc_id l3_epc_id INTEGER;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.4.1.20';
-- modify end

COMMIT;