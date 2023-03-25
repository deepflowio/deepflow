START TRANSACTION;

-- modify start, add upgrade sql

UPDATE alarm_policy SET sub_view_metrics="[{\"METRIC_LABEL\":\"load\",\"return_field_description\":\"持续 5 分钟 (系统负载/CPU总数)\",\"unit\":\"%\"}]", sub_view_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server.monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Avg(`metrics.load1`)/Avg(`metrics.cpu_num`) AS `load`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host_ip`\",\"METRICS\":[\"Avg(`metrics.load1`)/Avg(`metrics.cpu_num`) AS `load`\"]}]}", name="控制器系统负载高" WHERE name="控制器负载高";

UPDATE alarm_policy SET sub_view_metrics="[{\"METRIC_LABEL\":\"disk_used_percent\",\"return_field_description\":\"磁盘用量百分比\",\"unit\":\"%\"}]", sub_view_params="{\"DATABASE\":\"ext_metrics\",\"TABLE\":\"influxdb.disk\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Last(`metrics.used_percent`) AS `disk_used_percent`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host_ip`, `tag.path`\",\"METRICS\":[\"Last(`metrics.used_percent`) AS `disk_used_percent`\"]}]}" WHERE name="控制器磁盘空间不足";

UPDATE alarm_policy SET sub_view_metrics="[{\"METRIC_LABEL\":\"used_bytes\",\"return_field_description\":\"持续 5 分钟 (内存用量/阈值)\",\"unit\":\"%\"}]", sub_view_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Last(`metrics.memory`)*1024*1024/Avg(`metrics.max_memory`) AS `used_bytes`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Last(`metrics.memory`)*1024*1024/Avg(`metrics.max_memory`) AS `used_bytes`\"]}]}" WHERE name="采集器内存超限";

UPDATE alarm_policy SET sub_view_metrics="[{\"METRIC_LABEL\":\"load\",\"return_field_description\":\"持续 5 分钟 (系统负载/CPU总数)\",\"unit\":\"%\"}]", sub_view_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server.monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Avg(`metrics.load1`)*100/Avg(`metrics.cpu_num`) AS `load`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host_ip`\",\"METRICS\":[\"Avg(`metrics.load1`)*100/Avg(`metrics.cpu_num`) AS `load`\"]}]}", name="数据节点系统负载高" WHERE name="数据节点负载高";

UPDATE alarm_policy SET sub_view_metrics="[{\"METRIC_LABEL\":\"cpu_usage\",\"return_field_description\":\"持续 5 分钟 (CPU用量/阈值)\",\"unit\":\"%\"}]", sub_view_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Avg(`metrics.cpu_percent`)*100/Avg(`metrics.max_cpus`) AS `cpu_usage`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Avg(`metrics.cpu_percent`)*100/Avg(`metrics.max_cpus`) AS `cpu_usage`\"]}]}", name="采集器 CPU 超限" WHERE name="采集器CPU超限";

UPDATE alarm_policy SET sub_view_metrics="[{\"METRIC_LABEL\":\"used_bytes\",\"return_field_description\":\"持续 5 分钟 (系统空闲内存百分比/阈值)\",\"unit\":\"%\"}]", sub_view_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Avg(`metrics.sys_free_memory`)*100/Avg(`metrics.system_free_memory_limit`) AS `used_bytes`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Avg(`metrics.sys_free_memory`)*100/Avg(`metrics.system_free_memory_limit`) AS `used_bytes`\"]}]}", name="采集器所在系统空闲内存低" WHERE name="采集器系统空闲内存比例超限";

UPDATE alarm_policy SET sub_view_metrics="[{\"METRIC_LABEL\":\"disk_used_percent\",\"return_field_description\":\"磁盘用量百分比\",\"unit\":\"%\"}]" WHERE name="数据节点磁盘空间不足";

UPDATE alarm_policy SET sub_view_metrics="[{\"METRIC_LABEL\":\"delay\",\"return_field_description\":\"资源同步滞后时间\",\"unit\":\" 秒\"}]", name="K8s 资源同步滞后" WHERE name="K8s容器信息同步滞后";

UPDATE alarm_policy SET sub_view_metrics="[{\"METRIC_LABEL\":\"log_counter_error\",\"return_field_description\":\"最近 1 分钟 ERR 日志总条数\",\"unit\":\" 条\"}]", name="采集器 ERR 日志过多" WHERE name="采集器的ERR日志条数超限";

UPDATE alarm_policy SET sub_view_metrics="[{\"METRIC_LABEL\":\"log_counter_warning\",\"return_field_description\":\"最近 1 分钟 WARN 日志总条数\",\"unit\":\" 条\"}]", name="采集器 WARN 日志过多" WHERE name="采集器的WARN日志条数超限";

UPDATE alarm_policy SET sub_view_metrics="[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"至少一个授权文件剩余有效期\", \"return_field_unit\": \" 天\"}}]", name="DeepFlow 授权过期" WHERE name="DeepFlow授权过期";

UPDATE alarm_policy SET sub_view_metrics="[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"至少一个授权文件剩余有效期\", \"return_field_unit\": \" 天\"}}]", name="DeepFlow 授权即将过期" WHERE name="DeepFlow授权不足30天";

UPDATE alarm_policy SET sub_view_metrics="[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"余额可用天数\", \"return_field_unit\": \" 天\"}}]", name="DeepFlow 服务停止" WHERE name="DeepFlow停止服务";

UPDATE alarm_policy SET sub_view_metrics="[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"余额预估可用天数\", \"return_field_unit\": \" 天\"}}]", name="DeepFlow 服务即将停止" WHERE name="DeepFlow预估可用天数不足30天";

UPDATE alarm_policy SET sub_view_metrics="[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"最近 1 分钟云资源同步异常次数\", \"return_field_unit\": \" 次\"}}]", name="云资源同步异常" WHERE name="云平台同步异常";

UPDATE alarm_policy SET sub_view_metrics="[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"最近 1 分钟无效策略自动删除条数\", \"return_field_unit\": \" 次\"}}]", name="无效策略自动删除" WHERE name="策略自动删除";

UPDATE alarm_policy SET sub_view_metrics="[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"最近 1 分钟进程停止次数\", \"return_field_unit\": \" 次\"}}]" WHERE name="进程停止";

UPDATE alarm_policy SET sub_view_metrics="[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"最近 1 分钟进程启动次数\", \"return_field_unit\": \" 次\"}}]" WHERE name="进程启动";

UPDATE alarm_policy SET sub_view_metrics="[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"最近 1 分钟失联次数\", \"return_field_unit\": \" 次\"}}]" WHERE name="数据节点失联";

UPDATE alarm_policy SET sub_view_metrics="[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"最近 1 分钟失联次数\", \"return_field_unit\": \" 次\"}}]" WHERE name="控制器失联";

UPDATE alarm_policy SET sub_view_metrics="[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"最近 1 分钟失联次数\", \"return_field_unit\": \" 次\"}}]" WHERE name="采集器失联";

UPDATE alarm_policy SET sub_view_metrics="[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"最近 1 分钟异常状态个数\", \"return_field_unit\": \" 个\"}}]" WHERE name="采集器异常";

UPDATE alarm_policy SET sub_view_metrics="[{\"METRIC_LABEL\":\"rx_drop_packets\",\"return_field_description\":\"最近 1 分钟 ingester.recviver.metrics.invalid\",\"unit\":\"\"}]", sub_view_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server.ingester.recviver\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.invalid`) AS `rx_drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.invalid`) AS `rx_drop_packets`\"]}]}", name="数据节点数据丢失 (ingester.recviver.metrics.invalid)" WHERE name="数据节点丢包(ingester.recviver)";

UPDATE alarm_policy SET sub_view_metrics="[{\"METRIC_LABEL\":\"rx_drop_packets\",\"return_field_description\":\"最近 1 分钟 ingester.queue.metrics.overwritten\",\"unit\":\"\"}]", name="数据节点数据丢失 (ingester.queue.metrics.overwritten)" WHERE name="数据节点丢包(ingester.queue)";

UPDATE alarm_policy SET sub_view_metrics="[{\"METRIC_LABEL\":\"rx_drop_packets\",\"return_field_description\":\"最近 1 分钟 ingester.decoder.metrics.drop_count\",\"unit\":\"\"}]", name="数据节点数据丢失 (ingester.decoder.metrics.drop_count)" WHERE name="数据节点丢包(ingester.decoder.drop_count)";

UPDATE alarm_policy SET sub_view_metrics="[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 dispatcher.metrics.kernel_drops\",\"unit\":\"\"}]", name="采集器数据丢失 (dispatcher.metrics.kernel_drops)" WHERE name="采集器丢包(dispatcher)";

UPDATE alarm_policy SET sub_view_metrics="[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 queue.metrics.overwritten\",\"unit\":\"\"}]", name="采集器数据丢失 (queue.metrics.overwritten)" WHERE name="采集器丢包(queue)";

UPDATE alarm_policy SET sub_view_metrics="[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 l7_session_aggr.metrics.throttle-drop\",\"unit\":\"\"}]", name="采集器数据丢失 (l7_session_aggr.metrics.throttle-drop)" WHERE name="采集器丢包(l7_session_aggr)";

UPDATE alarm_policy SET sub_view_metrics="[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 flow_aggr.metrics.drop-in-throttle\",\"unit\":\"\"}]", name="采集器数据丢失 (flow_aggr.metrics.drop-in-throttle)" WHERE name="采集器丢包(flow_aggr)";

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(user_id, sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, 1, "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server.ingester.ckwriter\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.write_failed_count`) AS `rx_drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.write_failed_count`) AS `rx_drop_packets`\"]}]}",
    "[{\"METRIC_LABEL\":\"rx_drop_packets\",\"unit\":\"\"}]",
    "数据节点数据丢失 (ingester.ckwriter.metrics.write_failed_count)",  0, 1, 1, 21, 1, "", "", "rx_drop_packets", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(user_id, sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, 1, "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_ebpf_collector\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.kern_lost`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.kern_lost`) AS `drop_packets`\"]}]}",
    "[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 ebpf_collector.metrics.kern_lost\",\"unit\":\"\"}]",
    "采集器数据丢失 (ebpf_collector.metrics.kern_lost)",  0, 1, 1, 21, 1, "", "", "drop_packets", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(user_id, sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, 1, "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_ebpf_collector\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.user_enqueue_lost`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.kernuser_enqueue_lost_lost`) AS `drop_packets`\"]}]}",
    "[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 ebpf_collector.metrics.user_enqueue_lost\",\"unit\":\"\"}]",
    "采集器数据丢失 (ebpf_collector.metrics.user_enqueue_lost)",  0, 1, 1, 21, 1, "", "", "drop_packets", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(user_id, sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, 1, "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_dispatcher\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.retired`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.retired`) AS `drop_packets`\"]}]}",
    "[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 dispatcher.metrics.retired\",\"unit\":\"\"}]",
    "采集器数据丢失 (dispatcher.metrics.retired)",  0, 1, 1, 21, 1, "", "", "drop_packets", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(user_id, sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, 1, "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_dispatcher\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.invalid_packets`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.invalid_packets`) AS `drop_packets`\"]}]}",
    "[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 dispatcher.metrics.invalid_packets\",\"unit\":\"\"}]",
    "采集器数据丢失 (dispatcher.metrics.invalid_packets)",  0, 1, 1, 21, 1, "", "", "drop_packets", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(user_id, sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, 1, "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_dispatcher\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.err`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.err`) AS `drop_packets`\"]}]}",
    "[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 dispatcher.metrics.err\",\"unit\":\"\"}]",
    "采集器数据丢失 (dispatcher.metrics.err)",  0, 1, 1, 21, 1, "", "", "drop_packets", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(user_id, sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, 1, "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_flow_map\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.drop_before_window`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.drop_before_window`) AS `drop_packets`\"]}]}",
    "[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 flow_map.metrics.drop_before_window\",\"unit\":\"\"}]",
    "采集器数据丢失 (flow_map.metrics.drop_before_window)",  0, 1, 1, 21, 1, "", "", "drop_packets", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(user_id, sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, 1, "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_flow_aggr\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.drop-before-window`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.drop-before-window`) AS `drop_packets`\"]}]}",
    "[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 flow_aggr.metrics.err\",\"unit\":\"\"}]",
    "采集器数据丢失 (flow_aggr.metrics.drop-before-window)",  0, 1, 1, 21, 1, "", "", "drop_packets", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(user_id, sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, 1, "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_quadruple_generator\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.drop-before-window`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.drop-before-window`) AS `drop_packets`\"]}]}",
    "[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 quadruple_generator.metrics.drop_before_window\",\"unit\":\"\"}]",
    "采集器数据丢失 (quadruple_generator.metrics.drop-before-window)",  0, 1, 1, 21, 1, "", "", "drop_packets", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(user_id, sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, 1, "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_collector\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.drop-before-window`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.drop-before-window`) AS `drop_packets`\"]}]}",
    "[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 collector.metrics.drop_before_window\",\"unit\":\"\"}]",
    "采集器数据丢失 (collector.metrics.drop-before-window)",  0, 1, 1, 21, 1, "", "", "drop_packets", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(user_id, sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, 1, "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_collector\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.drop-inactive`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.drop-inactive`) AS `drop_packets`\"]}]}",
    "[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 collector.metrics.drop-inactive\",\"unit\":\"\"}]",
    "采集器数据丢失 (collector.metrics.drop-inactive)",  0, 1, 1, 21, 1, "", "", "drop_packets", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(user_id, sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, 1, "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_collect_sender\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.dropped`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.dropped`) AS `drop_packets`\"]}]}",
    "[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 collect_sender.metrics.drop-inactive\",\"unit\":\"\"}]",
    "采集器数据丢失 (collect_sender.metrics.dropped)",  0, 1, 1, 21, 1, "", "", "drop_packets", 1, NULL, @lcuuid);

DELETE FROM alarm_policy WHERE name IN ("数据节点丢包(ingester.trident_adapter)", "数据节点丢包(ingester.decoder.l7_dns_drop_count)", "数据节点丢包(ingester.decoder.l7_http_drop_count)", "数据节点写入失败");


-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.2.1.30';
-- modify end

COMMIT;
