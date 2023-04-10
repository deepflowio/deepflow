START TRANSACTION;

-- modify start, add upgrade sql

UPDATE alarm_policy SET sub_view_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server.monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Avg(`metrics.load1`)*100/Avg(`metrics.cpu_num`) AS `load`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host_ip`\",\"METRICS\":[\"Avg(`metrics.load1`)*100/Avg(`metrics.cpu_num`) AS `load`\"]}]}" WHERE name="控制器系统负载高";

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.2.1.32';
-- modify end

COMMIT;
