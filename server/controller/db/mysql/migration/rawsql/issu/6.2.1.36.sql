START TRANSACTION;

-- modify start, add upgrade sql

UPDATE alarm_policy SET sub_view_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Min(`metrics.memory`*100/`metrics.max_memory`) AS `used_bytes`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Min(`metrics.memory`*100/`metrics.max_memory`) AS `used_bytes`\"]}]}" WHERE name="采集器内存超限";

UPDATE alarm_policy SET sub_view_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\":\"null\",\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Min(`metrics.sys_free_memory`*100/`metrics.system_free_memory_limit`) AS `used_bytes`\",\"WHERE\":\"`metrics.system_free_memory_limit`!=0\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Min(`metrics.sys_free_memory`*100/`metrics.system_free_memory_limit`) AS `used_bytes`\"]}]}" WHERE name="采集器所在系统空闲内存低";

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.2.1.36';
-- modify end

COMMIT;