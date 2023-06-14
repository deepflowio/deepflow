START TRANSACTION;

-- modify start, add upgrade sql


UPDATE alarm_policy SET sub_view_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Min(`metrics.cpu_percent`/`metrics.max_cpus`) AS `cpu_usage`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Min(`metrics.cpu_percent`/`metrics.max_cpus`) AS `cpu_usage`\"]}]}" WHERE name="采集器 CPU 超限";


-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.3.1.5';
-- modify end

COMMIT;
