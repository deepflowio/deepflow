START TRANSACTION;

-- modify start, add upgrade sql

UPDATE alarm_policy SET sub_view_metrics="[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 flow_map.metrics.drop_by_window\",\"unit\":\"\"}]", query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_flow_map\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.drop_by_window`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.drop_by_window`) AS `drop_packets`\"]}]}", name="采集器数据丢失 (flow_map.metrics.drop_by_window)" WHERE name="采集器数据丢失 (flow_map.metrics.drop_before_window)";

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.3.1.60';
-- modify end

COMMIT;
