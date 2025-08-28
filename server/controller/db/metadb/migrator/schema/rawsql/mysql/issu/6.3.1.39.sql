START TRANSACTION;

-- modify start, add upgrade sql

CREATE TABLE IF NOT EXISTS alarm_policy_backups AS SELECT * FROM alarm_policy;

DELETE FROM alarm_policy;

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_error, lcuuid)
    values(1, "过滤项: N/A | 分组项: 采集器", "", "/v1/alarm/vtap-lost/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"最近 1 分钟失联次数\", \"return_field_unit\": \" 次\"}}]", "采集器失联",  1, 1, 1, 20, 1, "", "", "{\"displayName\":\"sysalarm_value\", \"unit\": \"次\"}", "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
    values(1, "过滤项: N/A | 分组项: tag.host_ip", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server.monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Min(`metrics.load1`*100/`metrics.cpu_num`) AS `load`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host_ip`, `tag.host`\",\"METRICS\":[\"Min(`metrics.load1`*100/`metrics.cpu_num`) AS `load`\"]}]}",
    "[{\"METRIC_LABEL\":\"load\",\"return_field_description\":\"持续 5 分钟 (系统负载/CPU总数)\",\"unit\":\"%\"}]", "控制器系统负载高",  0, 1, 1, 21, 1, "", "", "{\"displayName\":\"load\", \"unit\": \"%\"}", "{\"OP\":\">=\",\"VALUE\":70}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
    values(1, "过滤项: N/A | 分组项: tag.host_ip", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server.monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Min(`metrics.load1`*100/`metrics.cpu_num`) AS `load`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host_ip`, `tag.host`\",\"METRICS\":[\"Min(`metrics.load1`*100/`metrics.cpu_num`) AS `load`\"]}]}",
    "[{\"METRIC_LABEL\":\"load\",\"return_field_description\":\"持续 5 分钟 (系统负载/CPU总数)\",\"unit\":\"%\"}]", "数据节点系统负载高",  0, 1, 1, 21, 1, "", "", "{\"displayName\":\"load\", \"unit\": \"%\"}", "{\"OP\":\">=\",\"VALUE\":70}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_critical, lcuuid)
    values(1, "过滤项: N/A | 分组项: 采集器", "", "/v1/alarm/vtap-exception/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"最近 1 分钟异常状态个数\", \"return_field_unit\": \" 个\"}}]", "采集器异常",  1, 1, 1, 20, 1, "", "", "{\"displayName\":\"sysalarm_value\", \"unit\": \"个\"}", "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_critical, lcuuid)
    values(1, "过滤项: N/A | 分组项: 控制器", "", "/v1/alarm/controller-lost/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"最近 1 分钟失联次数\", \"return_field_unit\": \" 次\"}}]", "控制器失联",  2, 1, 1, 20, 1, "", "", "{\"displayName\":\"sysalarm_value\", \"unit\": \"次\"}", "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_error, lcuuid)
    values(1, "过滤项: N/A | 分组项: 数据节点", "", "/v1/alarm/analyzer-lost/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"最近 1 分钟失联次数\", \"return_field_unit\": \" 次\"}}]", "数据节点失联",  2, 1, 1, 20, 1, "", "", "{\"displayName\":\"sysalarm_value\", \"unit\": \"次\"}", "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
    values(1, "过滤项: N/A | 分组项: tag.host_ip, tag.path", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"ext_metrics\",\"TABLE\":\"influxdb.disk\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Last(`metrics.used_percent`) AS `disk_used_percent`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host_ip`, `tag.path`, `tag.host`\",\"METRICS\":[\"Last(`metrics.used_percent`) AS `disk_used_percent`\"]}]}",
    "[{\"METRIC_LABEL\":\"disk_used_percent\",\"return_field_description\":\"磁盘用量百分比\",\"unit\":\"%\"}]", "控制器磁盘空间不足",  0, 1, 1, 21, 1, "", "", "{\"displayName\":\"disk_used_percent\", \"unit\": \"%\"}", "{\"OP\":\">=\",\"VALUE\":70}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
    values(1, "过滤项: N/A | 分组项: tag.host_ip, tag.path, tag.host", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"ext_metrics\",\"TABLE\":\"influxdb.disk\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Last(`metrics.used_percent`) AS `disk_used_percent`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host_ip`, `tag.path`, `tag.host`\",\"METRICS\":[\"Last(`metrics.used_percent`) AS `disk_used_percent`\"]}]}",
    "[{\"METRIC_LABEL\":\"disk_used_percent\",\"return_field_description\":\"磁盘用量百分比\",\"unit\":\"%\"}]", "数据节点磁盘空间不足",  0, 1, 1, 21, 1, "", "", "{\"displayName\":\"disk_used_percent\", \"unit\": \"%\"}", "{\"OP\":\">=\",\"VALUE\":70}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
    values(1, "过滤项: N/A | 分组项: tag.host", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Min(`metrics.cpu_percent`/`metrics.max_cpus`) AS `cpu_usage`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Min(`metrics.cpu_percent`/`metrics.max_cpus`) AS `cpu_usage`\"]}]}",
    "[{\"METRIC_LABEL\":\"cpu_usage\",\"return_field_description\":\"持续 5 分钟 (CPU用量/阈值)\",\"unit\":\"%\"}]", "采集器 CPU 超限",  0, 1, 1, 21, 1, "", "", "{\"displayName\":\"cpu_usage\", \"unit\": \"%\"}", "{\"OP\":\">=\",\"VALUE\":70}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
    values(1, "过滤项: N/A | 分组项: tag.host", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Min(`metrics.memory`*100/`metrics.max_memory`) AS `used_bytes`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Min(`metrics.memory`*100/`metrics.max_memory`) AS `used_bytes`\"]}]}",
    "[{\"METRIC_LABEL\":\"used_bytes\",\"return_field_description\":\"持续 5 分钟 (内存用量/阈值)\",\"unit\":\"%\"}]", "采集器内存超限",  0, 1, 1, 21, 1, "", "", "{\"displayName\":\"used_bytes\", \"unit\": \"%\"}", "{\"OP\":\">=\",\"VALUE\":70}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field, agg,
    threshold_warning, lcuuid)
    values(1, "过滤项: N/A | 分组项: host", "", "/v1/stats/querier/UniversalPromHistory", "{\"DATABASE\":\"\",\"include_history\":\"true\",\"PROM_SQL\":\"delta(min(deepflow_system__deepflow_agent_monitor__create_time)by(host)[1m:])\",\"interval\":60,\"metric\":\"process_start\",\"time_tag\":\"toi\"}",
    "[{\"METRIC_LABEL\":\"process_start\",\"return_field_description\":\"最近 1 分钟进程启动时间变化\",\"unit\":\" 毫秒\"}]", "进程启动",  0, 1, 1, 20, 1, "", "", "{\"displayName\":\"process_start\", \"unit\": \"毫秒\"}", 1, "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field, agg,
    threshold_warning, lcuuid)
    values(1, "过滤项: N/A | 分组项: 主机名, 进程", "", "/v1/alarm/process-end/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"最近 1 分钟进程停止次数\", \"return_field_unit\": \"次\"}}]", "进程停止",  0, 1, 1, 20, 1, "", "", "{\"displayName\":\"sysalarm_value\", \"unit\": \"次\"}", 1, "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field, agg,
    threshold_warning, lcuuid)
    values(1, "过滤项: N/A | 分组项: *", "", "/v1/alarm/policy-event/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"最近 1 分钟无效策略自动删除条数\", \"return_field_unit\": \"次\"}}]", "无效策略自动删除",  0, 1, 1, 22, 1, "", "", "{\"displayName\":\"sysalarm_value\", \"unit\": \"次\"}", 1, "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_error, lcuuid)
    values(1, "过滤项: N/A | 分组项: *", "", "/v1/alarm/platform-event/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"最近 1 分钟云资源同步异常次数\", \"return_field_unit\": \"次\"}}]", "云资源同步异常",  1, 1, 1, 23, 1, "", "", "{\"displayName\":\"sysalarm_value\", \"unit\": \"次\"}", "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field, data_level, agg, delay,
    threshold_error, lcuuid)
    values(1, "过滤项: N/A | 分组项: *", "", "/v1/alarm/voucher-30days/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"余额预估可用天数\", \"return_field_unit\": \"天\"}}]", "DeepFlow 服务即将停止",  1, 1, 1, 24, 1, "", "", "{\"displayName\":\"sysalarm_value\", \"unit\": \"天\"}", "1d", 1, 0, "{\"OP\":\"<=\",\"VALUE\":30}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field, data_level, agg, delay,
    threshold_critical, lcuuid)
    values(1, "过滤项: N/A | 分组项: *", "", "/v1/alarm/voucher-0days/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"余额可用天数\", \"return_field_unit\": \"天\"}}]", "DeepFlow 服务停止",  2, 1, 1, 24, 1, "", "", "{\"displayName\":\"sysalarm_value\", \"unit\": \"天\"}", "1d", 1, 0, "{\"OP\":\"<=\",\"VALUE\":0}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field, data_level, agg, delay,
    threshold_error, lcuuid)
    values(1, "过滤项: N/A | 分组项: *", "","/v1/alarm/license-30days/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"至少一个授权文件剩余有效期\", \"return_field_unit\": \"天\"}}]", "DeepFlow 授权即将过期",  1, 1, 1, 24, 1, "", "", "{\"displayName\":\"sysalarm_value\", \"unit\": \"天\"}", "1d", 1, 0, "{\"OP\":\"<=\",\"VALUE\":30}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field, data_level, agg, delay,
    threshold_critical, lcuuid)
    values(1, "过滤项: N/A | 分组项: *", "", "/v1/alarm/license-0days/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"至少一个授权文件剩余有效期\", \"return_field_unit\": \"天\"}}]", "DeepFlow 授权过期",  2, 1, 1, 24, 1, "", "", "{\"displayName\":\"sysalarm_value\", \"unit\": \"天\"}", "1d", 1, 0, "{\"OP\":\"<=\",\"VALUE\":0}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
    values(1, "过滤项: N/A | 分组项: tag.host", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_monitor\",\"include_history\":\"true\",\"interval\":60,\"fill\":\"null\",\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Min(`metrics.sys_free_memory`*100/`metrics.system_free_memory_limit`) AS `used_bytes`\",\"WHERE\":\"`metrics.system_free_memory_limit`!=0\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Min(`metrics.sys_free_memory`*100/`metrics.system_free_memory_limit`) AS `used_bytes`\"]}]}",
    "[{\"METRIC_LABEL\":\"used_bytes\",\"return_field_description\":\"持续 5 分钟 (系统空闲内存百分比/阈值)\",\"unit\":\"%\"}]", "采集器所在系统空闲内存低",  0, 1, 1, 21, 1, "", "", "{\"displayName\":\"used_bytes\", \"unit\": \"%\"}", "{\"OP\":\"<=\",\"VALUE\":150}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
    values(1, "过滤项: N/A | 分组项: tag.host", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_log_counter\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.warning`) AS `log_counter_warning`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.warning`) AS `log_counter_warning`\"]}]}",
    "[{\"METRIC_LABEL\":\"log_counter_warning\",\"return_field_description\":\"最近 1 分钟 WARN 日志总条数\",\"unit\":\" 条\"}]", "采集器 WARN 日志过多",  0, 1, 1, 20, 1, "", "", "{\"displayName\":\"log_counter_warning\", \"unit\": \"条\"}", "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_error, lcuuid)
    values(1, "过滤项: N/A | 分组项: tag.host", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_log_counter\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.error`) AS `log_counter_error`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.error`) AS `log_counter_error`\"]}]}",
    "[{\"METRIC_LABEL\":\"log_counter_error\",\"return_field_description\":\"最近 1 分钟 ERR 日志总条数\",\"unit\":\" 条\"}]", "采集器 ERR 日志过多",  1, 1, 1, 20, 1, "", "", "{\"displayName\":\"log_counter_error\", \"unit\": \"条\"}", "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_error, lcuuid)
    values(1, "过滤项: N/A | 分组项: tag.cluster_id", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server_controller_genesis_k8sinfo_delay\",\"include_history\":\"true\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Last(`metrics.avg`) AS `delay`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.cluster_id`\",\"METRICS\":[\"Last(`metrics.avg`) AS `delay`\"]}]}",
    "[{\"METRIC_LABEL\":\"delay\",\"return_field_description\":\"资源同步滞后时间\",\"unit\":\" 秒\"}]", "K8s 资源同步滞后",  1, 1, 1, 23, 1, "", "", "{\"displayName\":\"delay\", \"unit\": \"秒\"}", "{\"OP\":\">=\",\"VALUE\":600}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
    values(1, "过滤项: N/A | 分组项: tag.host", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_dispatcher\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.kernel_drops`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.kernel_drops`) AS `drop_packets`\"]}]}",
     "[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 dispatcher.metrics.kernel_drops\",\"unit\":\"\"}]",
     "采集器数据丢失 (dispatcher.metrics.kernel_drops)",  0, 1, 1, 21, 1, "", "", "{\"displayName\":\"drop_packets\", \"unit\": \"\"}", "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
    values(1, "过滤项: N/A | 分组项: tag.host", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_queue\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.overwritten`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.overwritten`) AS `drop_packets`\"]}]}",
     "[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 queue.metrics.overwritten\",\"unit\":\"\"}]",
     "采集器数据丢失 (queue.metrics.overwritten)",  0, 1, 1, 21, 1, "", "", "{\"displayName\":\"drop_packets\", \"unit\": \"\"}", "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
    values(1, "过滤项: N/A | 分组项: tag.host", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_l7_session_aggr\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.throttle-drop`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.throttle-drop`) AS `drop_packets`\"]}]}",
     "[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 l7_session_aggr.metrics.throttle-drop\",\"unit\":\"\"}]",
     "采集器数据丢失 (l7_session_aggr.metrics.throttle-drop)",  0, 1, 1, 21, 1, "", "", "{\"displayName\":\"drop_packets\", \"unit\": \"\"}", "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
    values(1, "过滤项: N/A | 分组项: tag.host", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_flow_aggr\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.drop-in-throttle`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.drop-in-throttle`) AS `drop_packets`\"]}]}",
    "[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 flow_aggr.metrics.drop-in-throttle\",\"unit\":\"\"}]",
     "采集器数据丢失 (flow_aggr.metrics.drop-in-throttle)",  0, 1, 1, 21, 1, "", "", "{\"displayName\":\"drop_packets\", \"unit\": \"\"}", "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
    values(1, "过滤项: N/A | 分组项: tag.host", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_ebpf_collector\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.kern_lost`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.kern_lost`) AS `drop_packets`\"]}]}",
    "[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 ebpf_collector.metrics.kern_lost\",\"unit\":\"\"}]",
     "采集器数据丢失 (ebpf_collector.metrics.kern_lost)",  0, 1, 1, 21, 1, "", "", "{\"displayName\":\"drop_packets\", \"unit\": \"\"}", "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
    values(1, "过滤项: N/A | 分组项: tag.host", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_ebpf_collector\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.user_enqueue_lost`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.kernuser_enqueue_lost_lost`) AS `drop_packets`\"]}]}",
    "[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 ebpf_collector.metrics.user_enqueue_lost\",\"unit\":\"\"}]",
     "采集器数据丢失 (ebpf_collector.metrics.user_enqueue_lost)",  0, 1, 1, 21, 1, "", "", "{\"displayName\":\"drop_packets\", \"unit\": \"\"}", "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
    values(1, "过滤项: N/A | 分组项: tag.host", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_dispatcher\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.invalid_packets`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.invalid_packets`) AS `drop_packets`\"]}]}",
    "[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 dispatcher.metrics.invalid_packets\",\"unit\":\"\"}]",
     "采集器数据丢失 (dispatcher.metrics.invalid_packets)",  0, 1, 1, 21, 1, "", "", "{\"displayName\":\"drop_packets\", \"unit\": \"\"}", "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
    values(1, "过滤项: N/A | 分组项: tag.host", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_dispatcher\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.err`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.err`) AS `drop_packets`\"]}]}",
    "[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 dispatcher.metrics.err\",\"unit\":\"\"}]",
     "采集器数据丢失 (dispatcher.metrics.err)",  0, 1, 1, 21, 1, "", "", "{\"displayName\":\"drop_packets\", \"unit\": \"\"}", "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
    values(1, "过滤项: N/A | 分组项: tag.host", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_flow_map\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.drop_before_window`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.drop_before_window`) AS `drop_packets`\"]}]}",
    "[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 flow_map.metrics.drop_before_window\",\"unit\":\"\"}]",
     "采集器数据丢失 (flow_map.metrics.drop_before_window)",  0, 1, 1, 21, 1, "", "", "{\"displayName\":\"drop_packets\", \"unit\": \"\"}", "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
    values(1, "过滤项: N/A | 分组项: tag.host", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_flow_aggr\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.drop-before-window`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.drop-before-window`) AS `drop_packets`\"]}]}",
    "[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 flow_aggr.metrics.drop-before-window\",\"unit\":\"\"}]",
     "采集器数据丢失 (flow_aggr.metrics.drop-before-window)",  0, 1, 1, 21, 1, "", "", "{\"displayName\":\"drop_packets\", \"unit\": \"\"}", "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
    values(1, "过滤项: N/A | 分组项: tag.host", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_quadruple_generator\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.drop-before-window`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.drop-before-window`) AS `drop_packets`\"]}]}",
    "[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 quadruple_generator.metrics.drop_before_window\",\"unit\":\"\"}]",
     "采集器数据丢失 (quadruple_generator.metrics.drop-before-window)",  0, 1, 1, 21, 1, "", "", "{\"displayName\":\"drop_packets\", \"unit\": \"\"}", "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
    values(1, "过滤项: N/A | 分组项: tag.host", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_collector\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.drop-before-window`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.drop-before-window`) AS `drop_packets`\"]}]}",
    "[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 collector.metrics.drop_before_window\",\"unit\":\"\"}]",
     "采集器数据丢失 (collector.metrics.drop-before-window)",  0, 1, 1, 21, 1, "", "", "{\"displayName\":\"drop_packets\", \"unit\": \"\"}", "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
    values(1, "过滤项: N/A | 分组项: tag.host", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_collector\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.drop-inactive`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.drop-inactive`) AS `drop_packets`\"]}]}",
    "[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 collector.metrics.drop-inactive\",\"unit\":\"\"}]",
     "采集器数据丢失 (collector.metrics.drop-inactive)",  0, 1, 1, 21, 1, "", "", "{\"displayName\":\"drop_packets\", \"unit\": \"\"}", "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
    values(1, "过滤项: N/A | 分组项: tag.host", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_collect_sender\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.dropped`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.dropped`) AS `drop_packets`\"]}]}",
    "[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 collect_sender.metrics.dropped\",\"unit\":\"\"}]",
     "采集器数据丢失 (collect_sender.metrics.dropped)",  0, 1, 1, 21, 1, "", "", "{\"displayName\":\"drop_packets\", \"unit\": \"\"}", "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
    values(1, "过滤项: N/A | 分组项: tag.host", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server.ingester.recviver\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.invalid`) AS `rx_drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.invalid`) AS `rx_drop_packets`\"]}]}",
    "[{\"METRIC_LABEL\":\"rx_drop_packets\",\"return_field_description\":\"最近 1 分钟 ingester.recviver.metrics.invalid\",\"unit\":\"\"}]",
    "数据节点数据丢失 (ingester.recviver.metrics.invalid)",  0, 1, 1, 21, 1, "", "", "{\"displayName\":\"rx_drop_packets\", \"unit\": \"\"}", "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
    values(1, "过滤项: N/A | 分组项: tag.host", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server.ingester.queue\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.overwritten`) AS `rx_drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.overwritten`) AS `rx_drop_packets`\"]}]}",
     "[{\"METRIC_LABEL\":\"rx_drop_packets\",\"return_field_description\":\"最近 1 分钟 ingester.queue.metrics.overwritten\",\"unit\":\"\"}]",
     "数据节点数据丢失 (ingester.queue.metrics.overwritten)",  0, 1, 1, 21, 1, "", "", "{\"displayName\":\"rx_drop_packets\", \"unit\": \"\"}", "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
    values(1, "过滤项: N/A | 分组项: tag.host", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server.ingester.decoder\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.drop_count`) AS `rx_drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.drop_count`) AS `rx_drop_packets`\"]}]}",
     "[{\"METRIC_LABEL\":\"rx_drop_packets\",\"return_field_description\":\"最近 1 分钟 ingester.decoder.metrics.drop_count\",\"unit\":\"\"}]",
     "数据节点数据丢失 (ingester.decoder.metrics.drop_count)",  0, 1, 1, 21, 1, "", "", "{\"displayName\":\"rx_drop_packets\", \"unit\": \"\"}", "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
    values(1, "过滤项: N/A | 分组项: tag.host", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server.ingester.ckwriter\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.write_failed_count`) AS `rx_drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.write_failed_count`) AS `rx_drop_packets`\"]}]}",
     "[{\"METRIC_LABEL\":\"rx_drop_packets\",\"return_field_description\":\"最近 1 分钟 ingester.ckwriter.metrics.write_failed_count\",\"unit\":\"\"}]",
     "数据节点数据丢失 (ingester.ckwriter.metrics.write_failed_count)",  0, 1, 1, 21, 1, "", "", "{\"displayName\":\"rx_drop_packets\", \"unit\": \"\"}", "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid);

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.3.1.39';
-- modify end

COMMIT;
