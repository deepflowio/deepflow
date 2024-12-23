START TRANSACTION;

UPDATE alarm_policy SET sub_view_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server.monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Min(`metrics.load1`*100/`metrics.cpu_num`) AS `load`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host_ip`, `tag.host`\",\"METRICS\":[\"Min(`metrics.load1`*100/`metrics.cpu_num`) AS `load`\"]}]}" WHERE name="控制器系统负载高";
UPDATE alarm_policy SET sub_view_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server.monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Min(`metrics.load1`*100/`metrics.cpu_num`) AS `load`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host_ip`, `tag.host`\",\"METRICS\":[\"Min(`metrics.load1`*100/`metrics.cpu_num`) AS `load`\"]}]}" WHERE name="数据节点系统负载高";
UPDATE alarm_policy SET sub_view_params="{\"DATABASE\":\"ext_metrics\",\"TABLE\":\"influxdb.disk\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Last(`metrics.used_percent`) AS `disk_used_percent`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host_ip`, `tag.path`, `tag.host`\",\"METRICS\":[\"Last(`metrics.used_percent`) AS `disk_used_percent`\"]}]}" WHERE name="控制器磁盘空间不足";
UPDATE alarm_policy SET sub_view_params="{\"DATABASE\":\"ext_metrics\",\"TABLE\":\"influxdb.disk\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Last(`metrics.used_percent`) AS `disk_used_percent`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host_ip`, `tag.path`, `tag.host`\",\"METRICS\":[\"Last(`metrics.used_percent`) AS `disk_used_percent`\"]}]}" WHERE name="数据节点磁盘空间不足";


-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.3.1.24';
-- modify end

COMMIT;
