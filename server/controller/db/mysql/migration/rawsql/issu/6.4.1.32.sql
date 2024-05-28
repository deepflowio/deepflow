START TRANSACTION;

-- modify start, add upgrade sql

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

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.4.1.32';
-- modify end

COMMIT;
