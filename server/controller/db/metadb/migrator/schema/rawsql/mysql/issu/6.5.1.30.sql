START TRANSACTION;

-- modify start, add upgrade sql

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_monitor\",\"interval\":60,\"fill\": \"none\",\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"(Min(`metrics.cpu_percent`/`metrics.max_millicpus`)*1000) AS `cpu_usage`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"(Min(`metrics.cpu_percent`/`metrics.max_millicpus`)*1000) AS `cpu_usage`\"]}]}" WHERE name="采集器 CPU 超限";

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
    SELECT 1, 1, "过滤项: N/A | 分组项: tag.host", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_flow_map\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.drop_by_capacity`) AS `flow_map.metrics.drop_by_capacity`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.drop_by_capacity`) AS `flow_map.metrics.drop_by_capacity`\"]}]}",
    "[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 flow_map.metrics.drop_by_capacity\",\"unit\":\"\"}]",
     "采集器数据丢失 (flow_map.metrics.drop_by_capacity)",  0, 1, 1, 21, 1, "", "", "{\"displayName\":\"flow_map.metrics.drop_by_capacity\", \"unit\": \"\"}", "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid
     WHERE NOT EXISTS (
    SELECT * FROM alarm_policy WHERE name="采集器数据丢失 (flow_map.metrics.drop_by_capacity)"
);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
    SELECT 1, 1, "过滤项: N/A | 分组项: tag.db, tag.table, tag.partition", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server_ingester_force_delete_clickhouse_data\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Count(row) AS `force_delete_clickhouse_data_count`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.db`, `tag.table`, `tag.partition`\",\"METRICS\":[\"Count(row) AS `force_delete_clickhouse_data_count`\"]}]}",
    "[{\"METRIC_LABEL\":\"force_delete_clickhouse_data_count\",\"return_field_description\":\"最近 1 分钟 数据库修改次数\",\"unit\":\"次\"}]", "数据节点数据强制删除",  0, 1, 1, 21, 1, "", "", "{\"displayName\":\"force_delete_clickhouse_data_count\", \"unit\": \"次\"}", "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid
WHERE NOT EXISTS (
    SELECT * FROM alarm_policy WHERE name="数据节点数据强制删除"
);

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.5.1.30';
-- modify end

COMMIT;
