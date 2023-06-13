ALTER TABLE data_source ADD COLUMN display_name CHAR(64) AFTER id;
ALTER TABLE data_source ADD COLUMN data_table_collection CHAR(64) AFTER display_name;
ALTER TABLE data_source RENAME COLUMN name TO data_table;


START TRANSACTION;

UPDATE data_source SET display_name='指标（秒级）', data_table_collection='flow_metrics.vtap_flow*' WHERE id=1;
UPDATE data_source SET display_name='指标（分钟级）', data_table_collection='flow_metrics.vtap_flow*' WHERE id=3;
UPDATE data_source SET display_name='流日志', data_table_collection='flow_log', data_table='l4_flow_log', tsdb_type='l4_flow_log' WHERE id=6;
UPDATE data_source SET display_name='指标（秒级）', data_table_collection='flow_metrics.vtap_app*' WHERE id=7;
UPDATE data_source SET display_name='指标（分钟级）', data_table_collection='flow_metrics.vtap_app*' WHERE id=8;
UPDATE data_source SET display_name='调用日志', data_table_collection='flow_log', data_table='l7_flow_log', tsdb_type='l7_flow_log' WHERE id=9;
UPDATE data_source SET display_name='TCP 时序数据', data_table_collection='flow_log', data_table='l4_packet', tsdb_type='l4_packet' WHERE id=10;
UPDATE data_source SET display_name='PCAP 数据', data_table_collection='flow_log',  data_table='l7_packet', tsdb_type='l7_packet' WHERE id=11;
UPDATE data_source SET display_name='系统监控数据' WHERE id=12;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.3.1.12';

COMMIT;

