INSERT INTO sys_configuration (id, param_name, value, comments, lcuuid) VALUES (1, 'cloud_sync_timer', '60', 'unit: s', gen_random_uuid());
INSERT INTO sys_configuration (id, param_name, value, comments, lcuuid) VALUES (2, 'pcap_data_retention', '3', 'unit: day', gen_random_uuid());
INSERT INTO sys_configuration (id, param_name, value, comments, lcuuid) VALUES (3, 'system_data_retention', '7', 'unit: day', gen_random_uuid());
INSERT INTO sys_configuration (id, param_name, value, comments, lcuuid) VALUES (4, 'ntp_servers', '0.cn.pool.ntp.org', '', gen_random_uuid());

DO $$
DECLARE
    lcuuid UUID;
    short_uuid TEXT;
BEGIN
    lcuuid := gen_random_uuid();
    short_uuid := 'g-' || SUBSTRING(REPLACE(lcuuid::TEXT, '-', ''), 1, 10);
    INSERT INTO vtap_group (lcuuid, id, name, short_uuid, team_id) 
    VALUES (lcuuid, 1, 'default', short_uuid, 1);
END $$;

INSERT INTO data_source (id, display_name, data_table_collection, interval_time, retention_time, lcuuid)
VALUES (1, '网络-指标（秒级）', 'flow_metrics.network*', 1, 1 * 24, gen_random_uuid());

INSERT INTO data_source (id, display_name, data_table_collection, base_data_source_id, interval_time, retention_time, summable_metrics_operator, unsummable_metrics_operator, lcuuid)
VALUES (2, '网络-指标（分钟级）', 'flow_metrics.network*', 1, 60, 7 * 24, 'Sum', 'Avg', gen_random_uuid());

INSERT INTO data_source (id, display_name, data_table_collection, interval_time, retention_time, query_time, lcuuid)
VALUES (6, '网络-流日志', 'flow_log.l4_flow_log', 0, 3 * 24, 6 * 60, gen_random_uuid());

INSERT INTO data_source (id, display_name, data_table_collection, interval_time, retention_time, lcuuid)
VALUES (7, '应用-指标（秒级）', 'flow_metrics.application*', 1, 1 * 24, gen_random_uuid());

INSERT INTO data_source (id, display_name, data_table_collection, base_data_source_id, interval_time, retention_time, summable_metrics_operator, unsummable_metrics_operator, lcuuid)
VALUES (8, '应用-指标（分钟级）', 'flow_metrics.application*', 7, 60, 7 * 24, 'Sum', 'Avg', gen_random_uuid());

INSERT INTO data_source (id, display_name, data_table_collection, interval_time, retention_time, query_time, lcuuid)
VALUES (9, '应用-调用日志', 'flow_log.l7_flow_log', 0, 3 * 24, 6 * 60, gen_random_uuid());

INSERT INTO data_source (id, display_name, data_table_collection, interval_time, retention_time, lcuuid)
VALUES (10, '网络-TCP 时序数据', 'flow_log.l4_packet', 0, 3 * 24, gen_random_uuid());

INSERT INTO data_source (id, display_name, data_table_collection, interval_time, retention_time, lcuuid)
VALUES (11, '网络-PCAP 数据', 'flow_log.l7_packet', 0, 3 * 24, gen_random_uuid());

INSERT INTO data_source (id, display_name, data_table_collection, interval_time, retention_time, lcuuid)
VALUES (12, '租户侧监控数据', 'deepflow_tenant.*', 0, 7 * 24, gen_random_uuid());

INSERT INTO data_source (id, display_name, data_table_collection, interval_time, retention_time, lcuuid)
VALUES (13, '外部指标数据', 'ext_metrics.*', 0, 7 * 24, gen_random_uuid());

INSERT INTO data_source (id, display_name, data_table_collection, interval_time, retention_time, lcuuid)
VALUES (14, 'Prometheus 数据', 'prometheus.*', 0, 7 * 24, gen_random_uuid());

INSERT INTO data_source (id, display_name, data_table_collection, interval_time, retention_time, lcuuid)
VALUES (15, '事件-资源变更事件', 'event.event', 0, 30 * 24, gen_random_uuid());

INSERT INTO data_source (id, display_name, data_table_collection, interval_time, retention_time, lcuuid)
VALUES (16, '事件-文件读写事件', 'event.file_event', 0, 7 * 24, gen_random_uuid());

INSERT INTO data_source (id, display_name, data_table_collection, interval_time, retention_time, lcuuid)
VALUES (17, '事件-告警事件', 'event.alert_event', 0, 30 * 24, gen_random_uuid());

INSERT INTO data_source (id, display_name, data_table_collection, interval_time, retention_time, lcuuid)
VALUES (18, '应用-性能剖析', 'profile.in_process', 0, 3 * 24, gen_random_uuid());

INSERT INTO data_source (id, display_name, data_table_collection, interval_time, retention_time, lcuuid)
VALUES (19, '网络-网络策略', 'flow_metrics.traffic_policy', 60, 3 * 24, gen_random_uuid());

INSERT INTO data_source (id, display_name, data_table_collection, interval_time, retention_time, query_time, lcuuid)
VALUES (20, '日志-日志数据', 'application_log.log', 1, 30 * 24, 6 * 60, gen_random_uuid());

INSERT INTO data_source (id, display_name, data_table_collection, base_data_source_id, interval_time, retention_time, summable_metrics_operator, unsummable_metrics_operator, lcuuid)
VALUES (21, '网络-指标（小时级）', 'flow_metrics.network*', 2, 3600, 30 * 24, 'Sum', 'Avg', gen_random_uuid());

INSERT INTO data_source (id, display_name, data_table_collection, base_data_source_id, interval_time, retention_time, summable_metrics_operator, unsummable_metrics_operator, lcuuid)
VALUES (22, '网络-指标（天级）', 'flow_metrics.network*', 21, 86400, 30 * 24, 'Sum', 'Avg', gen_random_uuid());

INSERT INTO data_source (id, display_name, data_table_collection, base_data_source_id, interval_time, retention_time, summable_metrics_operator, unsummable_metrics_operator, lcuuid)
VALUES (23, '应用-指标（小时级）', 'flow_metrics.application*', 8, 3600, 30 * 24, 'Sum', 'Avg', gen_random_uuid());

INSERT INTO data_source (id, display_name, data_table_collection, base_data_source_id, interval_time, retention_time, summable_metrics_operator, unsummable_metrics_operator, lcuuid)
VALUES (24, '应用-指标（天级）', 'flow_metrics.application*', 23, 86400, 30 * 24, 'Sum', 'Avg', gen_random_uuid());

INSERT INTO data_source (id, display_name, data_table_collection, interval_time, retention_time, summable_metrics_operator, unsummable_metrics_operator, lcuuid)
VALUES (25, '应用-性能剖析指标', 'profile.in_process_metrics', 1, 3 * 24, 'Sum', 'Avg', gen_random_uuid());

INSERT INTO data_source (id, display_name, data_table_collection, interval_time, retention_time, summable_metrics_operator, unsummable_metrics_operator, lcuuid)
VALUES (26, '事件-文件读写指标', 'event.file_event_metrics', 1, 7 * 24, 'Sum', 'Avg', gen_random_uuid());

INSERT INTO region (id, name, lcuuid) VALUES (1, '系统默认', 'ffffffff-ffff-ffff-ffff-ffffffffffff');
INSERT INTO az (id, name, lcuuid, region, domain) VALUES (1, '系统默认', 'ffffffff-ffff-ffff-ffff-ffffffffffff', 'ffffffff-ffff-ffff-ffff-ffffffffffff', 'ffffffff-ffff-ffff-ffff-ffffffffffff');
INSERT INTO vl2 (state, name, net_type, isp, lcuuid, domain) 
VALUES (0, 'PublicNetwork', 3, 7, 'ffffffff-ffff-ffff-ffff-ffffffffffff', 'ffffffff-ffff-ffff-ffff-ffffffffffff');
INSERT INTO tap_type(name, value, vlan, description, lcuuid) 
VALUES ('云网络', 3, 768, '', gen_random_uuid());

INSERT INTO ch_device (devicetype, deviceid, name, icon_id, team_id, domain_id, sub_domain_id) VALUES (63999, 63999, 'Internet', -1, 0, 0, 0);
INSERT INTO ch_device (devicetype, deviceid, icon_id, team_id, domain_id, sub_domain_id) VALUES (64000, 64000, -10, 0, 0, 0);

INSERT INTO resource_version (name, version) VALUES ('prometheus', EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::INTEGER);

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state, app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field, threshold_error, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: 采集器', '', '/v1/alarm/vtap-lost/', '{}', '[{"OPERATOR": {"return_field": "sysalarm_value", "return_field_description": "最近 1 分钟失联次数", "return_field_unit": " 次"}}]', '采集器失联', 1, 1, 1, 20, 1, '', '', '{"displayName":"sysalarm_value", "unit": "次"}', '{"OP":">=", "VALUE":1}', gen_random_uuid()::text);

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state, app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field, threshold_critical, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: 采集器', '', '/v1/alarm/vtap-exception/', '{}', '[{"OPERATOR": {"return_field": "sysalarm_value", "return_field_description": "最近 1 分钟异常状态个数", "return_field_unit": " 个"}}]', '采集器异常',  1, 1, 1, 20, 1, '', '', '{"displayName":"sysalarm_value", "unit": "个"}', '{"OP":">=","VALUE":1}', gen_random_uuid()::text);

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state, app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field, threshold_warning, monitoring_interval, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: tag.host', '[{"type":"deepflow","tableName":"deepflow_agent_monitor","dbName":"deepflow_tenant","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.max_millicpus_ratio","METRIC_NAME":"metrics.max_millicpus_ratio","isTimeUnit":false,"type":1,"unit":"","checked":true,"operatorLv2":[{"operateLabel":"Math","mathOperator":"*","operatorValue":100}],"_key":"38813299-6cca-9b7f-4a08-5861fa7d6ee3","perOperator":"","operatorLv1":"Min","percentile":null,"markLine":null,"METRIC_LABEL":"cpu_usage","ORIGIN_METRIC_LABEL":"Math(Min(metrics.max_millicpus_ratio)*100)"}],"dataSource":"","condition":[{"dbName":"deepflow_tenant","tableName":"deepflow_agent_monitor","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.host"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.host"]},"inputMode":"free"}]}]',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_tenant","TABLE":"deepflow_agent_monitor","interval":60,"fill": "none","window_size":5,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Min(`metrics.max_millicpus_ratio`)*100 AS `cpu_usage`","WHERE":"1=1","GROUP_BY":"`tag.host`","METRICS":["Min(`metrics.max_millicpus_ratio`)*100 AS `cpu_usage`"]}]}',
    '[{"METRIC_LABEL":"cpu_usage","return_field_description":"持续 5 分钟 (CPU用量/阈值)","unit":"%"}]', '采集器 CPU 超限',  0, 1, 1, 21, 1, '', '', '{"displayName":"cpu_usage", "unit": "%"}', '{"OP":">=","VALUE":70}', '5m', gen_random_uuid()::text);

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, monitoring_interval, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: tag.host', '[{"type":"deepflow","tableName":"deepflow_agent_monitor","dbName":"deepflow_tenant","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.max_memory_ratio","METRIC_NAME":"metrics.max_memory_ratio","isTimeUnit":false,"type":1,"unit":"","checked":true,"operatorLv2":[{"operateLabel":"Math","mathOperator":"*","operatorValue":100}],"_key":"38813299-6cca-9b7f-4a08-5861fa7d6ee3","perOperator":"","operatorLv1":"Min","percentile":null,"markLine":null,"METRIC_LABEL":"used_bytes","ORIGIN_METRIC_LABEL":"Math(Min(metrics.max_memory_ratio)*100)"}],"dataSource":"","condition":[{"dbName":"deepflow_tenant","tableName":"deepflow_agent_monitor","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.host"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.host"]},"inputMode":"free"}]}]',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_tenant","TABLE":"deepflow_agent_monitor","interval":60,"fill": "none","window_size":5,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Min(`metrics.max_memory_ratio`)*100 AS `used_bytes`","WHERE":"1=1","GROUP_BY":"`tag.host`","METRICS":["Min(`metrics.max_memory_ratio`)*100 AS `used_bytes`"]}]}',
    '[{"METRIC_LABEL":"used_bytes","return_field_description":"持续 5 分钟 (内存用量/阈值)","unit":"%"}]', '采集器内存超限',  0, 1, 1, 21, 1, '', '', '{"displayName":"used_bytes", "unit": "%"}', '{"OP":">=","VALUE":70}', '5m', gen_random_uuid()::text);

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field, agg,
    threshold_warning, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: host', '', '/v1/stats/querier/UniversalPromHistory', '{"DATABASE":"","PROM_SQL":"delta(min(deepflow_tenant__deepflow_agent_monitor__create_time)by(host)[1m:10s])","interval":60,"metric":"process_start_time_delta","time_tag":"toi"}',
    '[{"METRIC_LABEL":"process_start","return_field_description":"最近 1 分钟进程启动时间变化","unit":" 毫秒"}]', '采集器重启',  0, 1, 1, 20, 1, '', '', '{"displayName":"process_start_time_delta", "unit": "毫秒"}', 1, '{"OP":">=","VALUE":1}', gen_random_uuid()::text);

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field, agg,
    threshold_warning, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: *', '', '/v1/alarm/policy-event/', '{}', '[{"OPERATOR": {"return_field": "sysalarm_value", "return_field_description": "最近 1 分钟无效策略自动删除条数", "return_field_unit": "次"}}]', '无效策略自动删除',  0, 1, 1, 22, 1, '', '', '{"displayName":"sysalarm_value", "unit": "次"}', 1, '{"OP":">=","VALUE":1}', gen_random_uuid()::text);

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_error, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: *', '', '/v1/alarm/platform-event/', '{}', '[{"OPERATOR": {"return_field": "sysalarm_value", "return_field_description": "最近 1 分钟云资源同步异常次数", "return_field_unit": "次"}}]', '云资源同步异常',  1, 1, 1, 23, 1, '', '', '{"displayName":"sysalarm_value", "unit": "次"}', '{"OP":">=","VALUE":1}', gen_random_uuid()::text);

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: tag.host', '[{"type":"deepflow","tableName":"deepflow_agent_log_counter","dbName":"deepflow_tenant","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.warning","METRIC_NAME":"metrics.warning","isTimeUnit":false,"type":1,"unit":"","cascaderLabel":"metrics.error","display_name":"--","hasDerivative":false,"isPrometheus":false,"operatorLv2":[],"operatorLv1":"Sum","perOperator":"","METRIC_LABEL":"log_counter_warning","checked":true,"percentile":null,"_key":"50d7a2a2-a14d-d202-1f3d-85fe7b9efac3","markLine":null,"ORIGIN_METRIC_LABEL":"Sum(metrics.warning)"}],"dataSource":"","condition":[{"dbName":"deepflow_tenant","tableName":"deepflow_agent_log_counter","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.host"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.host"]},"inputMode":"free"}]}]}]',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_tenant","TABLE":"deepflow_agent_log_counter","interval":60,"fill": "none","window_size":1,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Sum(`metrics.warning`) AS `log_counter_warning`","WHERE":"1=1","GROUP_BY":"`tag.host`","METRICS":["Sum(`metrics.warning`) AS `log_counter_warning`"]}]}',
    '[{"METRIC_LABEL":"log_counter_warning","return_field_description":"最近 1 分钟 WARN 日志总条数","unit":" 条"}]', '采集器 WARN 日志过多',  0, 1, 1, 20, 1, '', '', '{"displayName":"log_counter_warning", "unit": "条"}', '{"OP":">=","VALUE":1}', gen_random_uuid()::text);

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_error, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: tag.host', '[{"type":"deepflow","tableName":"deepflow_agent_log_counter","dbName":"deepflow_tenant","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.error","METRIC_NAME":"metrics.error","isTimeUnit":false,"type":1,"unit":"","cascaderLabel":"metrics.error","display_name":"--","hasDerivative":false,"isPrometheus":false,"operatorLv2":[],"operatorLv1":"Sum","perOperator":"","METRIC_LABEL":"log_counter_error","checked":true,"percentile":null,"_key":"50d7a2a2-a14d-d202-1f3d-85fe7b9efac3","markLine":null,"ORIGIN_METRIC_LABEL":"Sum(metrics.error)"}],"dataSource":"","condition":[{"dbName":"deepflow_tenant","tableName":"deepflow_agent_log_counter","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.host"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.host"]},"inputMode":"free"}]}]}]',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_tenant","TABLE":"deepflow_agent_log_counter","interval":60,"fill": "none","window_size":1,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Sum(`metrics.error`) AS `log_counter_error`","WHERE":"1=1","GROUP_BY":"`tag.host`","METRICS":["Sum(`metrics.error`) AS `log_counter_error`"]}]}',
    '[{"METRIC_LABEL":"log_counter_error","return_field_description":"最近 1 分钟 ERR 日志总条数","unit":" 条"}]', '采集器 ERR 日志过多',  1, 1, 1, 20, 1, '', '', '{"displayName":"log_counter_error", "unit": "条"}', '{"OP":">=","VALUE":1}', gen_random_uuid()::text);

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_error, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: tag.cluster_id', '[{"type":"deepflow","tableName":"controller_genesis_k8sinfo_delay","dbName":"deepflow_tenant","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.avg","METRIC_NAME":"metrics.avg","isTimeUnit":false,"type":1,"unit":"","cascaderLabel":"metrics.avg","display_name":"--","hasDerivative":false,"isPrometheus":false,"operatorLv2":[],"operatorLv1":"Last","perOperator":"","METRIC_LABEL":"delay","checked":true,"percentile":null,"_key":"8e92e913-a37f-ef34-8a4d-9169b96c6087","markLine":null,"ORIGIN_METRIC_LABEL":"Last(metrics.avg)"}],"dataSource":"","condition":[{"dbName":"deepflow_tenant","tableName":"controller_genesis_k8sinfo_delay","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.host"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.host"]},"inputMode":"free"}]}]}]',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_tenant","TABLE":"controller_genesis_k8sinfo_delay","interval":60,"fill": "none","window_size":1,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Last(`metrics.avg`) AS `delay`","WHERE":"1=1","GROUP_BY":"`tag.cluster_id`","METRICS":["Last(`metrics.avg`) AS `delay`"]}]}',
    '[{"METRIC_LABEL":"delay","return_field_description":"资源同步滞后时间","unit":" 秒"}]', 'K8s 资源同步滞后',  1, 1, 1, 23, 1, '', '', '{"displayName":"delay", "unit": "秒"}', '{"OP":">=","VALUE":600}', gen_random_uuid()::text);

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: tag.host', '[{"type":"deepflow","tableName":"deepflow_agent_dispatcher","dbName":"deepflow_tenant","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.kernel_drops","METRIC_NAME":"metrics.kernel_drops","isTimeUnit":false,"type":1,"unit":"","cascaderLabel":"metrics.err","display_name":"--","hasDerivative":false,"isPrometheus":false,"operatorLv2":[],"operatorLv1":"Sum","perOperator":"","METRIC_LABEL":"dispatcher.metrics.kernel_drops","checked":true,"percentile":null,"_key":"96fd254b-e6c1-4cc1-69fa-da5f4dd927ed","markLine":null,"ORIGIN_METRIC_LABEL":"Sum(metrics.kernel_drops)"}],"dataSource":"","condition":[{"dbName":"deepflow_tenant","tableName":"deepflow_agent_dispatcher","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.host"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.host"]},"inputMode":"free"}]}]}]',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_tenant","TABLE":"deepflow_agent_dispatcher","interval":60,"fill": "none","window_size":1,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Sum(`metrics.kernel_drops`) AS `dispatcher.metrics.kernel_drops`","WHERE":"1=1","GROUP_BY":"`tag.host`","METRICS":["Sum(`metrics.kernel_drops`) AS `dispatcher.metrics.kernel_drops`"]}]}',
    '[{"METRIC_LABEL":"drop_packets","return_field_description":"最近 1 分钟 dispatcher.metrics.kernel_drops","unit":""}]',
    '采集器数据丢失 (dispatcher.metrics.kernel_drops)',  0, 1, 1, 21, 1, '', '', '{"displayName":"dispatcher.metrics.kernel_drops", "unit": ""}', '{"OP":">=","VALUE":1}', gen_random_uuid()::text);

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: tag.host, tag.module', '[{"type":"deepflow","tableName":"deepflow_agent_queue","dbName":"deepflow_tenant","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.overwritten","METRIC_NAME":"metrics.overwritten","isTimeUnit":false,"type":1,"unit":"","cascaderLabel":"metrics.in","display_name":"--","hasDerivative":false,"isPrometheus":false,"operatorLv2":[],"operatorLv1":"Sum","perOperator":"","METRIC_LABEL":"queue.metrics.overwritten","checked":true,"percentile":null,"_key":"d61628e5-df0b-9337-6ee6-a3316a047e24","markLine":null,"ORIGIN_METRIC_LABEL":"Sum(metrics.overwritten)"}],"dataSource":"","condition":[{"dbName":"deepflow_tenant","tableName":"deepflow_agent_queue","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.host","tag.module"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.host","tag.module"]},"inputMode":"free"}]}]}]',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_tenant","TABLE":"deepflow_agent_queue","interval":60,"fill": "none","window_size":1,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Sum(`metrics.overwritten`) AS `queue.metrics.overwritten`","WHERE":"1=1","GROUP_BY":"`tag.host`, `tag.module`","METRICS":["Sum(`metrics.overwritten`) AS `queue.metrics.overwritten`"]}]}',
    '[{"METRIC_LABEL":"drop_packets","return_field_description":"最近 1 分钟 queue.metrics.overwritten","unit":""}]',
    '采集器数据丢失 (queue.metrics.overwritten)',  0, 1, 1, 21, 1, '', '', '{"displayName":"queue.metrics.overwritten", "unit": ""}', '{"OP":">=","VALUE":1}', gen_random_uuid()::text);

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: tag.host', '[{"type":"deepflow","tableName":"deepflow_agent_l7_session_aggr","dbName":"deepflow_tenant","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.throttle-drop","METRIC_NAME":"metrics.throttle-drop","isTimeUnit":false,"type":1,"unit":"","cascaderLabel":"metrics.cached","display_name":"--","hasDerivative":false,"isPrometheus":false,"operatorLv2":[],"operatorLv1":"Sum","perOperator":"","METRIC_LABEL":"l7_session_aggr.metrics.throttle-drop","checked":true,"percentile":null,"_key":"c511eb55-3d46-c7a2-bfed-ebb42d02493c","markLine":null,"ORIGIN_METRIC_LABEL":"Sum(metrics.throttle-drop)"}],"dataSource":"","condition":[{"dbName":"deepflow_tenant","tableName":"deepflow_agent_l7_session_aggr","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.host"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.host"]},"inputMode":"free"}]}]}]',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_tenant","TABLE":"deepflow_agent_l7_session_aggr","interval":60,"fill": "none","window_size":1,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Sum(`metrics.throttle-drop`) AS `l7_session_aggr.metrics.throttle-drop`","WHERE":"1=1","GROUP_BY":"`tag.host`","METRICS":["Sum(`metrics.throttle-drop`) AS `l7_session_aggr.metrics.throttle-drop`"]}]}',
    '[{"METRIC_LABEL":"drop_packets","return_field_description":"最近 1 分钟 l7_session_aggr.metrics.throttle-drop","unit":""}]',
    '采集器数据丢失 (l7_session_aggr.metrics.throttle-drop)',  0, 1, 1, 21, 1, '', '', '{"displayName":"l7_session_aggr.metrics.throttle-drop", "unit": ""}', '{"OP":">=","VALUE":1}', gen_random_uuid()::text);

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: tag.host', '[{"type":"deepflow","tableName":"deepflow_agent_flow_aggr","dbName":"deepflow_tenant","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.drop-in-throttle","METRIC_NAME":"metrics.drop-in-throttle","isTimeUnit":false,"type":1,"unit":"","cascaderLabel":"metrics.drop-before-window","display_name":"--","hasDerivative":false,"isPrometheus":false,"operatorLv2":[],"operatorLv1":"Sum","perOperator":"","METRIC_LABEL":"flow_aggr.metrics.drop-in-throttle","checked":true,"percentile":null,"_key":"e395cbb3-d5a2-283b-1b0a-834977bb6393","markLine":null,"ORIGIN_METRIC_LABEL":"Sum(metrics.drop-in-throttle)"}],"dataSource":"","condition":[{"dbName":"deepflow_tenant","tableName":"deepflow_agent_flow_aggr","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.host"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.host"]},"inputMode":"free"}]}]}]',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_tenant","TABLE":"deepflow_agent_flow_aggr","interval":60,"fill": "none","window_size":1,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Sum(`metrics.drop-in-throttle`) AS `flow_aggr.metrics.drop-in-throttle`","WHERE":"1=1","GROUP_BY":"`tag.host`","METRICS":["Sum(`metrics.drop-in-throttle`) AS `flow_aggr.metrics.drop-in-throttle`"]}]}',
    '[{"METRIC_LABEL":"drop_packets","return_field_description":"最近 1 分钟 flow_aggr.metrics.drop-in-throttle","unit":""}]',
    '采集器数据丢失 (flow_aggr.metrics.drop-in-throttle)',  0, 1, 1, 21, 1, '', '', '{"displayName":"flow_aggr.metrics.drop-in-throttle", "unit": ""}', '{"OP":">=","VALUE":1}', gen_random_uuid()::text);

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: tag.host', '[{"type":"deepflow","tableName":"deepflow_agent_ebpf_collector","dbName":"deepflow_tenant","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.kern_lost","METRIC_NAME":"metrics.kern_lost","isTimeUnit":false,"type":1,"unit":"","cascaderLabel":"metrics.boot_time_update_diff","display_name":"--","hasDerivative":false,"isPrometheus":false,"operatorLv2":[],"operatorLv1":"Sum","perOperator":"","METRIC_LABEL":"ebpf_collector.metrics.kern_lost","checked":true,"percentile":null,"_key":"8f28cb9b-ec39-d605-c056-53b0f2788c13","markLine":null,"ORIGIN_METRIC_LABEL":"Sum(metrics.kern_lost)"}],"dataSource":"","condition":[{"dbName":"deepflow_tenant","tableName":"deepflow_agent_ebpf_collector","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.host"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.host"]},"inputMode":"free"}]}]}]',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_tenant","TABLE":"deepflow_agent_ebpf_collector","interval":60,"fill": "none","window_size":1,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Sum(`metrics.kern_lost`) AS `ebpf_collector.metrics.kern_lost`","WHERE":"1=1","GROUP_BY":"`tag.host`","METRICS":["Sum(`metrics.kern_lost`) AS `ebpf_collector.metrics.kern_lost`"]}]}',
    '[{"METRIC_LABEL":"drop_packets","return_field_description":"最近 1 分钟 ebpf_collector.metrics.kern_lost","unit":""}]',
    '采集器数据丢失 (ebpf_collector.metrics.kern_lost)',  0, 1, 1, 21, 1, '', '', '{"displayName":"ebpf_collector.metrics.kern_lost", "unit": ""}', '{"OP":">=","VALUE":1}', gen_random_uuid()::text);

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: tag.host', '[{"type":"deepflow","tableName":"deepflow_agent_ebpf_collector","dbName":"deepflow_tenant","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.user_enqueue_lost","METRIC_NAME":"metrics.user_enqueue_lost","isTimeUnit":false,"type":1,"unit":"","cascaderLabel":"metrics.boot_time_update_diff","display_name":"--","hasDerivative":false,"isPrometheus":false,"operatorLv2":[],"operatorLv1":"Sum","perOperator":"","METRIC_LABEL":"ebpf_collector.metrics.user_enqueue_lost","checked":true,"percentile":null,"_key":"8f28cb9b-ec39-d605-c056-53b0f2788c13","markLine":null,"ORIGIN_METRIC_LABEL":"Sum(metrics.user_enqueue_lost)"}],"dataSource":"","condition":[{"dbName":"deepflow_tenant","tableName":"deepflow_agent_ebpf_collector","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.host"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.host"]},"inputMode":"free"}]}]}]',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_tenant","TABLE":"deepflow_agent_ebpf_collector","interval":60,"fill": "none","window_size":1,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Sum(`metrics.user_enqueue_lost`) AS `ebpf_collector.metrics.user_enqueue_lost`","WHERE":"1=1","GROUP_BY":"`tag.host`","METRICS":["Sum(`metrics.user_enqueue_lost`) AS `ebpf_collector.metrics.user_enqueue_lost`"]}]}',
    '[{"METRIC_LABEL":"drop_packets","return_field_description":"最近 1 分钟 ebpf_collector.metrics.user_enqueue_lost","unit":""}]',
    '采集器数据丢失 (ebpf_collector.metrics.user_enqueue_lost)',  0, 1, 1, 21, 1, '', '', '{"displayName":"ebpf_collector.metrics.user_enqueue_lost", "unit": ""}', '{"OP":">=","VALUE":1}', gen_random_uuid()::text);

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: tag.host', '[{"type":"deepflow","tableName":"deepflow_agent_dispatcher","dbName":"deepflow_tenant","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.invalid_packets","METRIC_NAME":"metrics.invalid_packets","isTimeUnit":false,"type":1,"unit":"","cascaderLabel":"metrics.err","display_name":"--","hasDerivative":false,"isPrometheus":false,"operatorLv2":[],"operatorLv1":"Sum","perOperator":"","METRIC_LABEL":"dispatcher.metrics.invalid_packets","checked":true,"percentile":null,"_key":"41f6303b-f31e-8b7e-83c8-67a8edf735af","markLine":null,"ORIGIN_METRIC_LABEL":"Sum(metrics.invalid_packets)"}],"dataSource":"","condition":[{"dbName":"deepflow_tenant","tableName":"deepflow_agent_dispatcher","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.host"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.host"]},"inputMode":"free"}]}]}]',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_tenant","TABLE":"deepflow_agent_dispatcher","interval":60,"fill": "none","window_size":1,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Sum(`metrics.invalid_packets`) AS `dispatcher.metrics.invalid_packets`","WHERE":"1=1","GROUP_BY":"`tag.host`","METRICS":["Sum(`metrics.invalid_packets`) AS `dispatcher.metrics.invalid_packets`"]}]}',
    '[{"METRIC_LABEL":"drop_packets","return_field_description":"最近 1 分钟 dispatcher.metrics.invalid_packets","unit":""}]',
    '采集器数据丢失 (dispatcher.metrics.invalid_packets)',  0, 1, 1, 21, 1, '', '', '{"displayName":"dispatcher.metrics.invalid_packets", "unit": ""}', '{"OP":">=","VALUE":1}', gen_random_uuid()::text);

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: tag.host', '[{"type":"deepflow","tableName":"deepflow_agent_dispatcher","dbName":"deepflow_tenant","dataSource":"","condition":[{"dbName":"deepflow_tenant","tableName":"deepflow_agent_dispatcher","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.host"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.host"]},"inputMode":"free"}]}],"metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.err","METRIC_NAME":"metrics.err","isTimeUnit":false,"type":1,"unit":"","checked":true,"operatorLv2":[],"_key":"6fb3545a-74eb-ac62-4e84-622c0265a840","perOperator":"","operatorLv1":"Sum","percentile":null,"markLine":null,"METRIC_LABEL":"dispatcher.metrics.err","ORIGIN_METRIC_LABEL":"Sum(metrics.err)"}]}]',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_tenant","TABLE":"deepflow_agent_dispatcher","interval":60,"fill": "none","window_size":1,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Sum(`metrics.err`) AS `dispatcher.metrics.err`","WHERE":"1=1","GROUP_BY":"`tag.host`","METRICS":["Sum(`metrics.err`) AS `dispatcher.metrics.err`"]}]}',
    '[{"METRIC_LABEL":"drop_packets","return_field_description":"最近 1 分钟 dispatcher.metrics.err","unit":""}]',
    '采集器数据丢失 (dispatcher.metrics.err)',  0, 1, 1, 21, 1, '', '', '{"displayName":"dispatcher.metrics.err", "unit": ""}', '{"OP":">=","VALUE":1}', gen_random_uuid()::text);

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: tag.host', '[{"type":"deepflow","tableName":"deepflow_agent_flow_map","dbName":"deepflow_tenant","dataSource":"","condition":[{"dbName":"deepflow_tenant","tableName":"deepflow_agent_flow_map","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.host"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.host"]},"inputMode":"free"}]}],"metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.drop_by_window","METRIC_NAME":"metrics.drop_by_window","isTimeUnit":false,"type":1,"unit":"","cascaderLabel":"metrics.closed","display_name":"--","hasDerivative":false,"isPrometheus":false,"operatorLv2":[],"operatorLv1":"Sum","perOperator":"","METRIC_LABEL":"flow_map.metrics.drop_by_window","checked":true,"percentile":null,"_key":"629edc91-d806-d7ac-bdea-517f46ad6530","markLine":null,"ORIGIN_METRIC_LABEL":"Sum(metrics.drop_by_window)"}]}',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_tenant","TABLE":"deepflow_agent_flow_map","interval":60,"fill": "none","window_size":1,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Sum(`metrics.drop_by_window`) AS `flow_map.metrics.drop_by_window`","WHERE":"1=1","GROUP_BY":"`tag.host`","METRICS":["Sum(`metrics.drop_by_window`) AS `flow_map.metrics.drop_by_window`"]}]}',
    '[{"METRIC_LABEL":"drop_packets","return_field_description":"最近 1 分钟 flow_map.metrics.drop_by_window","unit":""}]',
    '采集器数据丢失 (flow_map.metrics.drop_by_window)',  0, 1, 1, 21, 1, '', '', '{"displayName":"flow_map.metrics.drop_by_window", "unit": ""}', '{"OP":">=","VALUE":1}', (SELECT gen_random_uuid()));

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: tag.host', '[{"type":"deepflow","tableName":"deepflow_agent_flow_map","dbName":"deepflow_tenant","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.drop_by_capacity","METRIC_NAME":"metrics.drop_by_capacity","isTimeUnit":false,"type":1,"unit":"","cascaderLabel":"metrics.closed","display_name":"--","hasDerivative":false,"isPrometheus":false,"operatorLv2":[],"operatorLv1":"Sum","perOperator":"","METRIC_LABEL":"flow_map.metrics.drop_by_capacity","checked":true,"percentile":null,"_key":"988eb89d-d8cd-6827-d359-86b6c29fdbb6","markLine":null,"ORIGIN_METRIC_LABEL":"Sum(metrics.drop_by_capacity)"}],"dataSource":"","condition":[{"dbName":"deepflow_tenant","tableName":"deepflow_agent_flow_map","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.host"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.host"]},"inputMode":"free"}]}]}',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_tenant","TABLE":"deepflow_agent_flow_map","interval":60,"fill": "none","window_size":1,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Sum(`metrics.drop_by_capacity`) AS `flow_map.metrics.drop_by_capacity`","WHERE":"1=1","GROUP_BY":"`tag.host`","METRICS":["Sum(`metrics.drop_by_capacity`) AS `flow_map.metrics.drop_by_capacity`"]}]}',
    '[{"METRIC_LABEL":"drop_packets","return_field_description":"最近 1 分钟 flow_map.metrics.drop_by_capacity","unit":""}]',
    '采集器数据丢失 (flow_map.metrics.drop_by_capacity)',  0, 1, 1, 21, 1, '', '', '{"displayName":"flow_map.metrics.drop_by_capacity", "unit": ""}', '{"OP":">=","VALUE":1}', (SELECT gen_random_uuid()));

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: tag.host', '[{"type":"deepflow","tableName":"deepflow_agent_flow_aggr","dbName":"deepflow_tenant","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.drop-before-window","METRIC_NAME":"metrics.drop-before-window","isTimeUnit":false,"type":1,"unit":"","cascaderLabel":"metrics.drop-before-window","display_name":"--","hasDerivative":false,"isPrometheus":false,"operatorLv2":[],"operatorLv1":"Sum","perOperator":"","METRIC_LABEL":"flow_aggr.metrics.drop-before-window","checked":true,"percentile":null,"_key":"d5ebf837-b5b6-e853-7933-e09506a781ff","markLine":null,"ORIGIN_METRIC_LABEL":"Sum(metrics.drop-before-window)"}],"dataSource":"","condition":[{"dbName":"deepflow_tenant","tableName":"deepflow_agent_flow_aggr","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.host"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.host"]},"inputMode":"free"}]}]}',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_tenant","TABLE":"deepflow_agent_flow_aggr","interval":60,"fill": "none","window_size":1,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Sum(`metrics.drop-before-window`) AS `flow_aggr.metrics.drop-before-window`","WHERE":"1=1","GROUP_BY":"`tag.host`","METRICS":["Sum(`metrics.drop-before-window`) AS `flow_aggr.metrics.drop-before-window`"]}]}',
    '[{"METRIC_LABEL":"drop_packets","return_field_description":"最近 1 分钟 flow_aggr.metrics.drop-before-window","unit":""}]',
    '采集器数据丢失 (flow_aggr.metrics.drop-before-window)',  0, 1, 1, 21, 1, '', '', '{"displayName":"flow_aggr.metrics.drop-before-window", "unit": ""}', '{"OP":">=","VALUE":1}', (SELECT gen_random_uuid()));

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: tag.host', '[{"type":"deepflow","tableName":"deepflow_agent_quadruple_generator","dbName":"deepflow_tenant","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.drop-before-window","METRIC_NAME":"metrics.drop-before-window","isTimeUnit":false,"type":1,"unit":"","cascaderLabel":"metrics.drop-before-window","display_name":"--","hasDerivative":false,"isPrometheus":false,"operatorLv2":[],"operatorLv1":"Sum","perOperator":"","METRIC_LABEL":"quadruple_generator.metrics.drop-before-window","checked":true,"percentile":null,"_key":"79facee8-3875-df77-e375-2f7f955b0035","markLine":null,"ORIGIN_METRIC_LABEL":"Sum(metrics.drop-before-window)"}],"dataSource":"","condition":[{"dbName":"deepflow_tenant","tableName":"deepflow_agent_quadruple_generator","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.host"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.host"]},"inputMode":"free"}]}]}',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_tenant","TABLE":"deepflow_agent_quadruple_generator","interval":60,"fill": "none","window_size":1,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Sum(`metrics.drop-before-window`) AS `quadruple_generator.metrics.drop-before-window`","WHERE":"1=1","GROUP_BY":"`tag.host`","METRICS":["Sum(`metrics.drop-before-window`) AS `quadruple_generator.metrics.drop-before-window`"]}]}',
    '[{"METRIC_LABEL":"drop_packets","return_field_description":"最近 1 分钟 quadruple_generator.metrics.drop_before_window","unit":""}]',
    '采集器数据丢失 (quadruple_generator.metrics.drop-before-window)',  0, 1, 1, 21, 1, '', '', '{"displayName":"quadruple_generator.metrics.drop-before-window", "unit": ""}', '{"OP":">=","VALUE":1}', (SELECT gen_random_uuid()));

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: tag.host', '[{"type":"deepflow","tableName":"deepflow_agent_collector","dbName":"deepflow_tenant","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.drop-before-window","METRIC_NAME":"metrics.drop-before-window","isTimeUnit":false,"type":1,"unit":"","cascaderLabel":"metrics.drop-before-window","display_name":"--","hasDerivative":false,"isPrometheus":false,"operatorLv2":[],"operatorLv1":"Sum","perOperator":"","METRIC_LABEL":"collector.metrics.drop-before-window","checked":true,"percentile":null,"_key":"e63575a2-333a-b612-0b57-684387f80431","markLine":null,"ORIGIN_METRIC_LABEL":"Sum(metrics.drop-before-window)"}],"dataSource":"","condition":[{"dbName":"deepflow_tenant","tableName":"deepflow_agent_collector","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.host"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.host"]},"inputMode":"free"}]}]}',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_tenant","TABLE":"deepflow_agent_collector","interval":60,"fill": "none","window_size":1,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Sum(`metrics.drop-before-window`) AS `collector.metrics.drop-before-window`","WHERE":"1=1","GROUP_BY":"`tag.host`","METRICS":["Sum(`metrics.drop-before-window`) AS `collector.metrics.drop-before-window`"]}]}',
    '[{"METRIC_LABEL":"drop_packets","return_field_description":"最近 1 分钟 collector.metrics.drop_before_window","unit":""}]',
    '采集器数据丢失 (collector.metrics.drop-before-window)',  0, 1, 1, 21, 1, '', '', '{"displayName":"collector.metrics.drop-before-window", "unit": ""}', '{"OP":">=","VALUE":1}', (SELECT gen_random_uuid()));

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: tag.host', '[{"type":"deepflow","tableName":"deepflow_agent_collector","dbName":"deepflow_tenant","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.drop-inactive","METRIC_NAME":"metrics.drop-inactive","isTimeUnit":false,"type":1,"unit":"","cascaderLabel":"metrics.drop-before-window","display_name":"--","hasDerivative":false,"isPrometheus":false,"operatorLv2":[],"operatorLv1":"Sum","perOperator":"","METRIC_LABEL":"collector.metrics.drop-inactive","checked":true,"percentile":null,"_key":"e63575a2-333a-b612-0b57-684387f80431","markLine":null,"ORIGIN_METRIC_LABEL":"Sum(metrics.drop-inactive)"}],"dataSource":"","condition":[{"dbName":"deepflow_tenant","tableName":"deepflow_agent_collector","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.host"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.host"]},"inputMode":"free"}]}]}',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_tenant","TABLE":"deepflow_agent_collector","interval":60,"fill": "none","window_size":1,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Sum(`metrics.drop-inactive`) AS `collector.metrics.drop-inactive`","WHERE":"1=1","GROUP_BY":"`tag.host`","METRICS":["Sum(`metrics.drop-inactive`) AS `collector.metrics.drop-inactive`"]}]}',
    '[{"METRIC_LABEL":"drop_packets","return_field_description":"最近 1 分钟 collector.metrics.drop-inactive","unit":""}]',
    '采集器数据丢失 (collector.metrics.drop-inactive)',  0, 1, 1, 21, 1, '', '', '{"displayName":"collector.metrics.drop-inactive", "unit": ""}', '{"OP":">=","VALUE":1}', (SELECT gen_random_uuid()));

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: tag.host', '[{"type":"deepflow","tableName":"deepflow_agent_collect_sender","dbName":"deepflow_tenant","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.dropped","METRIC_NAME":"metrics.dropped","isTimeUnit":false,"type":1,"unit":"","cascaderLabel":"metrics.dropped","display_name":"--","hasDerivative":false,"isPrometheus":false,"operatorLv2":[],"operatorLv1":"Sum","perOperator":"","METRIC_LABEL":"collect_sender.metrics.dropped","checked":true,"percentile":null,"_key":"7848fead-8554-591f-b0da-dec4180fa576","markLine":null,"ORIGIN_METRIC_LABEL":"Sum(metrics.dropped)"}],"dataSource":"","condition":[{"dbName":"deepflow_tenant","tableName":"deepflow_agent_collect_sender","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.host"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.host"]},"inputMode":"free"}]}]}',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_tenant","TABLE":"deepflow_agent_collect_sender","interval":60,"fill": "none","window_size":1,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Sum(`metrics.dropped`) AS `collect_sender.metrics.dropped`","WHERE":"1=1","GROUP_BY":"`tag.host`","METRICS":["Sum(`metrics.dropped`) AS `collect_sender.metrics.dropped`"]}]}',
    '[{"METRIC_LABEL":"drop_packets","return_field_description":"最近 1 分钟 collect_sender.metrics.dropped","unit":""}]',
    '采集器数据丢失 (collect_sender.metrics.dropped)',  0, 1, 1, 21, 1, '', '', '{"displayName":"collect_sender.metrics.dropped", "unit": ""}', '{"OP":">=","VALUE":1}', (SELECT gen_random_uuid()));

INSERT INTO alarm_policy (
    user_id, tag_conditions, query_conditions, query_url, query_params, name, level, state,
    app_type, contrast_type, target_field, threshold_warning, lcuuid)
VALUES (
    1, '过滤项: tag.type = device_ip_connection', '[{"type":"deepflow","tableName":"deepflow_server_controller_resource_relation_exception","dbName":"deepflow_tenant","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.count","METRIC_NAME":"metrics.count","isTimeUnit":false,"type":1,"unit":["data","short"],"checked":true,"operatorLv2":[],"_key":"77b0ee61-e213-4d10-9342-bb172f861f39","perOperator":"","operatorLv1":"Sum","percentile":null,"markLine":null,"diffMarkLine":null,"METRIC_LABEL":"Sum(metrics.count)","ORIGIN_METRIC_LABEL":"Sum(metrics.count)"}],"condition":[{"dbName":"deepflow_tenant","tableName":"deepflow_server_controller_resource_relation_exception","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[{"key":"tag.type","op":"=","val":["device_ip_connection"]}],"groupBy":["_","tag.domain"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.domain"]},"inputMode":"free"}]}],"dataSource":""}]',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_tenant","TABLE":"deepflow_server_controller_resource_relation_exception","interval":60,"fill": "none","window_size":1,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Sum(`metrics.count`) AS `Sum(metrics.count)`","WHERE":"`tag.type`=''device_ip_connection''","GROUP_BY":"`tag.domain`","METRICS":["Sum(`metrics.count`) AS `Sum(metrics.count)`"]}]}',
    '云资源关联关系异常 (实例与IP)',  0, 1, 1, 1, '{"displayName":"Sum(metrics.count)","unit":""}', '{"OP":">=","VALUE":1}', (SELECT gen_random_uuid()));

INSERT INTO alarm_policy (
    user_id, tag_conditions, query_conditions, query_url, query_params, name, level, state,
    app_type, contrast_type, target_field, threshold_warning, lcuuid)
VALUES (
    1, '过滤项: tag.type = chost_pod_node_connection', '[{"type":"deepflow","tableName":"deepflow_server_controller_resource_relation_exception","dbName":"deepflow_tenant","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.count","METRIC_NAME":"metrics.count","isTimeUnit":false,"type":1,"unit":["data","short"],"checked":true,"operatorLv2":[],"_key":"77b0ee61-e213-4d10-9342-bb172f861f39","perOperator":"","operatorLv1":"Sum","percentile":null,"markLine":null,"diffMarkLine":null,"METRIC_LABEL":"Sum(metrics.count)","ORIGIN_METRIC_LABEL":"Sum(metrics.count)"}],"condition":[{"dbName":"deepflow_tenant","tableName":"deepflow_server_controller_resource_relation_exception","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[{"key":"tag.type","op":"=","val":["chost_pod_node_connection"]}],"groupBy":["_","tag.domain"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.domain"]},"inputMode":"free"}]}],"dataSource":""}]',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_tenant","TABLE":"deepflow_server_controller_resource_relation_exception","interval":60,"fill": "none","window_size":1,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Sum(`metrics.count`) AS `Sum(metrics.count)`","WHERE":"`tag.type`=''chost_pod_node_connection''","GROUP_BY":"`tag.domain`","METRICS":["Sum(`metrics.count`) AS `Sum(metrics.count)`"]}]}',
    '云资源关联关系异常 (云主机与容器节点)',  0, 1, 1, 1, '{"displayName":"Sum(metrics.count)","unit":""}', '{"OP":">=","VALUE":1}', (SELECT gen_random_uuid()));

INSERT INTO alarm_policy (
    user_id, tag_conditions, query_conditions, query_url, query_params, name, level, state,
    app_type, contrast_type, target_field, threshold_warning, lcuuid)
VALUES (
    1, '过滤项: N/A', '[{"type":"deepflow","tableName":"deepflow_server_controller_resource_sync_delay","dbName":"deepflow_tenant","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.max_delay","METRIC_NAME":"metrics.max_delay","isTimeUnit":false,"type":1,"unit":["data","short"],"checked":true,"operatorLv2":[],"_key":"77b0ee61-e213-4d10-9342-bb172f861f39","perOperator":"","operatorLv1":"Max","percentile":null,"markLine":null,"diffMarkLine":null,"METRIC_LABEL":"Max(metrics.max_delay)","ORIGIN_METRIC_LABEL":"Max(metrics.max_delay)"}],"condition":[{"dbName":"deepflow_tenant","tableName":"deepflow_server_controller_resource_sync_delay","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.domain"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.domain"]},"inputMode":"free"}]}],"dataSource":""}]',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_tenant","TABLE":"deepflow_server_controller_resource_sync_delay","interval":60,"fill": "none","window_size":1,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Max(`metrics.max_delay`) AS `Max(metrics.max_delay)`","WHERE":"1=1","GROUP_BY":"`tag.domain`","METRICS":["Max(`metrics.max_delay`) AS `Max(metrics.max_delay)`"]}]}',
    '云资源同步滞后 (云主机)',  0, 1, 1, 1, '{"displayName":"Max(metrics.max_delay)","unit":""}', '{"OP":">=","VALUE":150}', (SELECT gen_random_uuid()));

INSERT INTO alarm_policy (
    user_id, tag_conditions, query_conditions, query_url, query_params, name, level, state,
    app_type, contrast_type, target_field, threshold_warning, lcuuid)
VALUES (
    1, '过滤项: N/A', '[{"type":"deepflow","tableName":"deepflow_server_controller_resource_sync_delay","dbName":"deepflow_tenant","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.max_delay","METRIC_NAME":"metrics.max_delay","isTimeUnit":false,"type":1,"unit":["data","short"],"checked":true,"operatorLv2":[],"_key":"77b0ee61-e213-4d10-9342-bb172f861f39","perOperator":"","operatorLv1":"Max","percentile":null,"markLine":null,"diffMarkLine":null,"METRIC_LABEL":"Max(metrics.max_delay)","ORIGIN_METRIC_LABEL":"Max(metrics.max_delay)"}],"condition":[{"dbName":"deepflow_tenant","tableName":"deepflow_server_controller_resource_sync_delay","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.domain","tag.sub_domain"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.domain","tag.sub_domain"]},"inputMode":"free"}]}],"dataSource":""}]',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_tenant","TABLE":"deepflow_server_controller_resource_sync_delay","interval":60,"fill": "none","window_size":1,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Max(`metrics.max_delay`) AS `Max(metrics.max_delay)`","WHERE":"1=1","GROUP_BY":"`tag.domain`, `tag.sub_domain`","METRICS":["Max(`metrics.max_delay`) AS `Max(metrics.max_delay)`"]}]}',
    '云资源同步滞后 (POD)',  0, 1, 1, 1, '{"displayName":"Max(metrics.max_delay)","unit":""}', '{"OP":">=","VALUE":120}', (SELECT gen_random_uuid()));

INSERT INTO alarm_policy (
    user_id, tag_conditions, query_conditions, query_url, query_params, name, level, state,
    app_type, contrast_type, target_field, threshold_warning, lcuuid)
VALUES (
    1, '过滤项: N/A', '[{"type":"deepflow","tableName":"deepflow_server_controller_cloud_task_cost","dbName":"deepflow_tenant","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.cost","METRIC_NAME":"metrics.cost","isTimeUnit":false,"type":1,"unit":["data","short"],"checked":true,"operatorLv2":[],"_key":"77b0ee61-e213-4d10-9342-bb172f861f39","perOperator":"","operatorLv1":"AAvg","percentile":null,"markLine":null,"diffMarkLine":null,"METRIC_LABEL":"AAvg(metrics.cost)","ORIGIN_METRIC_LABEL":"AAvg(metrics.cost)"}],"condition":[{"dbName":"deepflow_tenant","tableName":"deepflow_server_controller_cloud_task_cost","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.domain"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.domain"]},"inputMode":"free"}]}],"dataSource":""}]',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_tenant","TABLE":"deepflow_server_controller_cloud_task_cost","interval":60,"fill": "none","window_size":1,"QUERIES":[{"QUERY_ID":"R1","SELECT":"AAvg(`metrics.cost`) AS `AAvg(metrics.cost)`","WHERE":"1=1","GROUP_BY":"`tag.domain`","METRICS":["AAvg(`metrics.cost`) AS `AAvg(metrics.cost)`"]}]}',
    '云资源同步滞后 (API 调用)',  0, 1, 1, 1, '{"displayName":"AAvg(metrics.cost)","unit":""}', '{"OP":">=","VALUE":300}', (SELECT gen_random_uuid()));
