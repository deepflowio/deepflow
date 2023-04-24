START TRANSACTION;

-- modify start, add upgrade sql

UPDATE alarm_policy SET sub_view_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server.monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Min(`metrics.load1`*100/`metrics.cpu_num`) AS `load`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host_ip`\",\"METRICS\":[\"Min(`metrics.load1`*100/`metrics.cpu_num`) AS `load`\"]}]}" WHERE name="控制器系统负载高";

UPDATE alarm_policy SET sub_view_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Min(`metrics.memory`*1024*1024/`metrics.max_memory`) AS `used_bytes`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Min(`metrics.memory`*1024*1024/`metrics.max_memory`) AS `used_bytes`\"]}]}" WHERE name="采集器内存超限";

UPDATE alarm_policy SET sub_view_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server.monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Min(`metrics.load1`*100/`metrics.cpu_num`) AS `load`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host_ip`\",\"METRICS\":[\"Min(`metrics.load1`*100`metrics.cpu_num`) AS `load`\"]}]}" WHERE name="数据节点系统负载高";

UPDATE alarm_policy SET sub_view_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Min(`metrics.cpu_percent`*100/`metrics.max_cpus`) AS `cpu_usage`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Min(`metrics.cpu_percent`*100/`metrics.max_cpus`) AS `cpu_usage`\"]}]}" WHERE name="采集器 CPU 超限";

UPDATE alarm_policy SET sub_view_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Min(`metrics.sys_free_memory`*100/`metrics.system_free_memory_limit`) AS `used_bytes`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Min(`metrics.sys_free_memory`*100/`metrics.system_free_memory_limit`) AS `used_bytes`\"]}]}" WHERE name="采集器所在系统空闲内存低";

UPDATE alarm_policy SET target_field="process_start", user_id=1, sub_view_url="/v1/stats/querier/UniversalHistory", sub_view_metrics="[{\"METRIC_LABEL\":\"process_start\",\"return_field_description\":\"最近 5 分钟进程启动时间变化\",\"unit\":\" 毫秒\"}]", sub_view_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Spread(`metrics.create_time`) AS `process_start`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Spread(`metrics.create_time`) AS `process_start`\"]}]}" WHERE name="进程启动";

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.2.1.35';
-- modify end

COMMIT;