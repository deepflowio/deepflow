START TRANSACTION;
UPDATE data_source SET data_table_collection='flow_metrics.vtap_app*'  WHERE data_table_collection='app' AND display_name in('1h', '1d');
UPDATE data_source SET data_table_collection='flow_metrics.vtap_flow*'  WHERE data_table_collection='flow' AND display_name in('1h', '1d');

UPDATE db_version SET version='6.3.1.41';

COMMIT;
