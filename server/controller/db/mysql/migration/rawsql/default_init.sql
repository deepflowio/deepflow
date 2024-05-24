set @lcuuid = (select uuid());
INSERT INTO alarm_policy(user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_critical, lcuuid)
    values(1, 1, "过滤项: N/A | 分组项: 控制器", "", "/v1/alarm/controller-lost/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"最近 1 分钟失联次数\", \"return_field_unit\": \" 次\"}}]", "控制器失联",  2, 1, 1, 20, 1, "", "", "{\"displayName\":\"sysalarm_value\", \"unit\": \"次\"}", "{\"OP\":\">=\",\"VALUE\":1}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
    values(1, 1, "过滤项: N/A | 分组项: tag.host_ip, tag.path, tag.host", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server_monitor_disk\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Last(`metrics.used_percent`) AS `disk_used_percent`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host_ip`, `tag.path`, `tag.host`\",\"METRICS\":[\"Last(`metrics.used_percent`) AS `disk_used_percent`\"]}]}",
    "[{\"METRIC_LABEL\":\"disk_used_percent\",\"return_field_description\":\"磁盘用量百分比\",\"unit\":\"%\"}]", "控制器磁盘空间不足",  0, 1, 1, 21, 1, "", "", "{\"displayName\":\"disk_used_percent\", \"unit\": \"%\"}", "{\"OP\":\">=\",\"VALUE\":70}", @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
    values(1, 1, "过滤项: N/A | 分组项: tag.host_ip", "", "/v1/stats/querier/UniversalHistory", "{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server_monitor\",\"interval\":60,\"fill\": \"none\",\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Min(`metrics.load1`*100/`metrics.cpu_num`) AS `load`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host_ip`, `tag.host`\",\"METRICS\":[\"Min(`metrics.load1`*100/`metrics.cpu_num`) AS `load`\"]}]}",
    "[{\"METRIC_LABEL\":\"load\",\"return_field_description\":\"持续 5 分钟 (系统负载/CPU总数)\",\"unit\":\"%\"}]", "控制器系统负载高",  0, 1, 1, 21, 1, "", "", "{\"displayName\":\"load\", \"unit\": \"%\"}", "{\"OP\":\">=\",\"VALUE\":70}", @lcuuid);
