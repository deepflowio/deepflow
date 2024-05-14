START TRANSACTION;

-- modify start, add upgrade sql

UPDATE alarm_policy SET sub_view_metrics="[{\"METRIC_LABEL\":\"force_delete_clickhouse_data_bytes_on_disk\",\"return_field_description\":\"最近 1 分钟数据节点数据强制删除\",\"unit\":\"字节\"}]", target_field="{\"displayName\":\"force_delete_clickhouse_data_bytes_on_disk\", \"unit\": \"字节\"}", query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server_ingester_force_delete_clickhouse_data\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.bytes_on_disk`) AS `force_delete_clickhouse_data_bytes_on_disk`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`, `tag.db`, `tag.table`, `tag.partition`\",\"METRICS\":[\"Sum(`metrics.bytes_on_disk`) AS `force_delete_clickhouse_data_bytes_on_disk`\"]}]}" WHERE name="数据节点数据强制删除";

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.5.1.31';
-- modify end

COMMIT;
