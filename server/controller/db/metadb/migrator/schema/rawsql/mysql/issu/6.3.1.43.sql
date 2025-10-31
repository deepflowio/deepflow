START TRANSACTION;

-- modify start, add upgrade sql

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server.monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\": \"none\",\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Min(`metrics.load1`*100/`metrics.cpu_num`) AS `load`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host_ip`, `tag.host`\",\"METRICS\":[\"Min(`metrics.load1`*100/`metrics.cpu_num`) AS `load`\"]}]}" WHERE name="控制器系统负载高";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server.monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\": \"none\",\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Min(`metrics.load1`*100/`metrics.cpu_num`) AS `load`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host_ip`, `tag.host`\",\"METRICS\":[\"Min(`metrics.load1`*100/`metrics.cpu_num`) AS `load`\"]}]}" WHERE name="数据节点系统负载高";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"ext_metrics\",\"TABLE\":\"influxdb.disk\",\"include_history\":\"true\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Last(`metrics.used_percent`) AS `disk_used_percent`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host_ip`, `tag.path`, `tag.host`\",\"METRICS\":[\"Last(`metrics.used_percent`) AS `disk_used_percent`\"]}]}" WHERE name="控制器磁盘空间不足";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"ext_metrics\",\"TABLE\":\"influxdb.disk\",\"include_history\":\"true\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Last(`metrics.used_percent`) AS `disk_used_percent`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host_ip`, `tag.path`, `tag.host`\",\"METRICS\":[\"Last(`metrics.used_percent`) AS `disk_used_percent`\"]}]}" WHERE name="数据节点磁盘空间不足";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\": \"none\",\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Min(`metrics.cpu_percent`/`metrics.max_cpus`) AS `cpu_usage`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Min(`metrics.cpu_percent`/`metrics.max_cpus`) AS `cpu_usage`\"]}]}" WHERE name="采集器 CPU 超限";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\": \"none\",\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Min(`metrics.memory`*100/`metrics.max_memory`) AS `used_bytes`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Min(`metrics.memory`*100/`metrics.max_memory`) AS `used_bytes`\"]}]}" WHERE name="采集器内存超限";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\": \"none\",\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Min(`metrics.sys_free_memory`*100/`metrics.system_free_memory_limit`) AS `used_bytes`\",\"WHERE\":\"`metrics.system_free_memory_limit`!=0\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Min(`metrics.sys_free_memory`*100/`metrics.system_free_memory_limit`) AS `used_bytes`\"]}]}" WHERE name="采集器所在系统空闲内存低";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_log_counter\",\"include_history\":\"true\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.warning`) AS `log_counter_warning`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.warning`) AS `log_counter_warning`\"]}]}" WHERE name="采集器 WARN 日志过多";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_log_counter\",\"include_history\":\"true\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.error`) AS `log_counter_error`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.error`) AS `log_counter_error`\"]}]}" WHERE name="采集器 ERR 日志过多";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server_controller_genesis_k8sinfo_delay\",\"include_history\":\"true\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Last(`metrics.avg`) AS `delay`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.cluster_id`\",\"METRICS\":[\"Last(`metrics.avg`) AS `delay`\"]}]}" WHERE name="K8s 资源同步滞后";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_dispatcher\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.kernel_drops`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.kernel_drops`) AS `drop_packets`\"]}]" WHERE name="采集器数据丢失 (dispatcher.metrics.kernel_drops)";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_queue\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.overwritten`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.overwritten`) AS `drop_packets`\"]}]}" WHERE name="采集器数据丢失 (queue.metrics.overwritten)";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_l7_session_aggr\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.throttle-drop`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.throttle-drop`) AS `drop_packets`\"]}]}" WHERE name="采集器数据丢失 (l7_session_aggr.metrics.throttle-drop)";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_flow_aggr\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.drop-in-throttle`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.drop-in-throttle`) AS `drop_packets`\"]}]}" WHERE name="采集器数据丢失 (flow_aggr.metrics.drop-in-throttle)";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_ebpf_collector\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.kern_lost`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.kern_lost`) AS `drop_packets`\"]}]}" WHERE name="采集器数据丢失 (ebpf_collector.metrics.kern_lost)";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_ebpf_collector\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.user_enqueue_lost`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.kernuser_enqueue_lost_lost`) AS `drop_packets`\"]}]}" WHERE name="采集器数据丢失 (ebpf_collector.metrics.user_enqueue_lost)";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_dispatcher\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.invalid_packets`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.invalid_packets`) AS `drop_packets`\"]}]}" WHERE name="采集器数据丢失 (dispatcher.metrics.invalid_packets)";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_dispatcher\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.err`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.err`) AS `drop_packets`\"]}]}" WHERE name="采集器数据丢失 (dispatcher.metrics.err)";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_flow_map\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.drop_before_window`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.drop_before_window`) AS `drop_packets`\"]}]}" WHERE name="采集器数据丢失 (flow_map.metrics.drop_before_window)";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_flow_aggr\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.drop-before-window`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.drop-before-window`) AS `drop_packets`\"]}]}" WHERE name="采集器数据丢失 (flow_aggr.metrics.drop-before-window)";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_quadruple_generator\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.drop-before-window`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.drop-before-window`) AS `drop_packets`\"]}]}" WHERE name="采集器数据丢失 (quadruple_generator.metrics.drop-before-window)";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_collector\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.drop-before-window`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.drop-before-window`) AS `drop_packets`\"]}]}" WHERE name="采集器数据丢失 (collector.metrics.drop-before-window)";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_collector\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.drop-inactive`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.drop-inactive`) AS `drop_packets`\"]}]}" WHERE name="采集器数据丢失 (collector.metrics.drop-inactive)";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_collect_sender\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.dropped`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.dropped`) AS `drop_packets`\"]}]}" WHERE name="采集器数据丢失 (collect_sender.metrics.dropped)";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server.ingester.recviver\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.invalid`) AS `rx_drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.invalid`) AS `rx_drop_packets`\"]}]}" WHERE name="数据节点数据丢失 (ingester.recviver.metrics.invalid)";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server.ingester.queue\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.overwritten`) AS `rx_drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.overwritten`) AS `rx_drop_packets`\"]}]}" WHERE name="数据节点数据丢失 (ingester.queue.metrics.overwritten)";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server.ingester.decoder\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.drop_count`) AS `rx_drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.drop_count`) AS `rx_drop_packets`\"]}]}" WHERE name="数据节点数据丢失 (ingester.decoder.metrics.drop_count)";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server.ingester.ckwriter\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.write_failed_count`) AS `rx_drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.write_failed_count`) AS `rx_drop_packets`\"]}]}" WHERE name="数据节点数据丢失 (ingester.ckwriter.metrics.write_failed_count)";

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.3.1.43';
-- modify end

COMMIT;
