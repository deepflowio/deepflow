START TRANSACTION;

-- modify start, add upgrade sql

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_flow_map\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.drop_by_window`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.drop_by_window`) AS `drop_packets`\"]}]}", name="采集器数据丢失 (flow_map.metrics.drop_by_window)" WHERE name="采集器数据丢失 (flow_map.metrics.drop-before-window)";

UPDATE alarm_policy SET tag_conditions="过滤项: N/A | 分组项: tag.host_ip, tag.path, tag.host", query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server_monitor_disk\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Last(`metrics.used_percent`) AS `disk_used_percent`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host_ip`, `tag.path`, `tag.host`\",\"METRICS\":[\"Last(`metrics.used_percent`) AS `disk_used_percent`\"]}]}" WHERE name="控制器磁盘空间不足";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server_monitor_disk\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Last(`metrics.used_percent`) AS `disk_used_percent`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host_ip`, `tag.path`, `tag.host`\",\"METRICS\":[\"Last(`metrics.used_percent`) AS `disk_used_percent`\"]}]}" WHERE name="数据节点磁盘空间不足";

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.4.1.14';
-- modify end

COMMIT;
