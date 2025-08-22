START TRANSACTION;

UPDATE data_source SET data_table_collection='flow_metrics.network*' where data_table_collection='flow_metrics.vtap_flow*';
UPDATE data_source SET data_table_collection='flow_metrics.application*' where data_table_collection='flow_metrics.vtap_app*';
UPDATE data_source SET data_table_collection='flow_metrics.traffic_policy' where data_table_collection='flow_metrics.vtap_acl';

UPDATE tap_type SET name='云网络' where name='虚拟网络';

-- update db_version to latest
UPDATE db_version SET version='6.5.1.7';

COMMIT;
