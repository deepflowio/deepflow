INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state, app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field, threshold_critical, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: 控制器', '', '/v1/alarm/controller-lost/', '{}', '[{"OPERATOR": {"return_field": "sysalarm_value", "return_field_description": "最近 1 分钟失联次数", "return_field_unit": " 次"}}]', '控制器失联', 2, 1, 1, 20, 1, '', '', '{"displayName":"sysalarm_value", "unit": "次"}', '{"OP":">=","VALUE":1}', gen_random_uuid());

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state, app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field, threshold_warning, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: tag.host_ip, tag.path, tag.host', '[{"type":"deepflow","tableName":"deepflow_server_monitor_disk","dbName":"deepflow_admin","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.used_percent","METRIC_NAME":"metrics.used_percent","isTimeUnit":false,"type":1,"unit":"","cascaderLabel":"metrics.free","display_name":"--","hasDerivative":false,"isPrometheus":false,"operatorLv2":[],"operatorLv1":"Last","perOperator":"","METRIC_LABEL":"disk_used_percent","checked":true,"percentile":null,"_key":"561bf802-10ae-4988-38f5-97001e896d8e","markLine":null,"ORIGIN_METRIC_LABEL":"Last(metrics.used_percent)"}],"dataSource":"","condition":{"dbName":"deepflow_admin","tableName":"deepflow_server_monitor_disk","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.host","tag.host_ip","tag.path"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.host","tag.host_ip","tag.path"]},"inputMode":"free"}]}}]', '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_admin","TABLE":"deepflow_server_monitor_disk","interval":60,"fill": "none","window_size":1,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Last(`metrics.used_percent`) AS `disk_used_percent`","WHERE":"1=1","GROUP_BY":"`tag.host_ip`, `tag.path`, `tag.host`","METRICS":["Last(`metrics.used_percent`) AS `disk_used_percent`"]}]}', '[{"METRIC_LABEL":"disk_used_percent","return_field_description":"磁盘用量百分比","unit":"%"}]', '控制器磁盘空间不足', 0, 1, 1, 21, 1, '', '', '{"displayName":"disk_used_percent", "unit": "%"}', '{"OP":">=","VALUE":70}', gen_random_uuid());

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state, app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field, threshold_warning, monitoring_interval, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: tag.host_ip, tag.host', '[{"type":"deepflow","tableName":"deepflow_server_monitor","dbName":"deepflow_admin","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.load1_by_cpu_num","METRIC_NAME":"metrics.load1_by_cpu_num","isTimeUnit":false,"type":1,"unit":"","checked":true,"operatorLv2":[{"operateLabel":"Math","mathOperator":"*","operatorValue":100}],"_key":"48c02f46-f3c3-9ad6-924e-502a82762e18","perOperator":"","operatorLv1":"Min","percentile":null,"markLine":null,"METRIC_LABEL":"load","ORIGIN_METRIC_LABEL":"Math(Min(metrics.load1_by_cpu_num)*100)"}],"dataSource":"","condition":{"dbName":"deepflow_admin","tableName":"deepflow_server_monitor","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.host","tag.host_ip"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.host","tag.host_ip"]},"inputMode":"free"}]}}]', '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_admin","TABLE":"deepflow_server_monitor","interval":60,"fill": "none","window_size":5,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Min(`metrics.load1_by_cpu_num`)*100 AS `load`","WHERE":"1=1","GROUP_BY":"`tag.host_ip`, `tag.host`","METRICS":["Min(`metrics.load1_by_cpu_num`)*100 AS `load`"]}]}', '[{"METRIC_LABEL":"load","return_field_description":"持续 5 分钟 (系统负载/CPU总数)","unit":"%"}]', '控制器系统负载高', 0, 1, 1, 21, 1, '', '', '{"displayName":"load", "unit": "%"}', '{"OP":">=","VALUE":70}', '5m', gen_random_uuid());

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state, app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field, threshold_warning, monitoring_interval, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: tag.host_ip, tag.host', '[{"type":"deepflow","tableName":"deepflow_server_monitor","dbName":"deepflow_admin","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.load1_by_cpu_num","METRIC_NAME":"metrics.load1_by_cpu_num","isTimeUnit":false,"type":1,"unit":"","checked":true,"operatorLv2":[{"operateLabel":"Math","mathOperator":"*","operatorValue":100}],"_key":"48c02f46-f3c3-9ad6-924e-502a82762e18","perOperator":"","operatorLv1":"Min","percentile":null,"markLine":null,"METRIC_LABEL":"load","ORIGIN_METRIC_LABEL":"Math(Min(metrics.load1_by_cpu_num)*100)"}],"dataSource":"","condition":{"dbName":"deepflow_admin","tableName":"deepflow_server_monitor","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.host","tag.host_ip"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.host","tag.host_ip"]},"inputMode":"free"}]}}]', '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_admin","TABLE":"deepflow_server_monitor","interval":60,"fill": "none","window_size":5,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Min(`metrics.load1_by_cpu_num`)*100 AS `load`","WHERE":"1=1","GROUP_BY":"`tag.host_ip`, `tag.host`","METRICS":["Min(`metrics.load1_by_cpu_num`)*100 AS `load`"]}]}', '[{"METRIC_LABEL":"load","return_field_description":"持续 5 分钟 (系统负载/CPU总数)","unit":"%"}]', '数据节点系统负载高', 0, 1, 1, 21, 1, '', '', '{"displayName":"load", "unit": "%"}', '{"OP":">=","VALUE":70}', '5m', gen_random_uuid());

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_error, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: 数据节点', '', '/v1/alarm/analyzer-lost/', '{}', '[{"OPERATOR": {"return_field": "sysalarm_value", "return_field_description": "最近 1 分钟失联次数", "return_field_unit": " 次"}}]', '数据节点失联',  2, 1, 1, 20, 1, '', '', '{"displayName":"sysalarm_value", "unit": "次"}', '{"OP":">=","VALUE":1}', gen_random_uuid());

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: tag.host_ip, tag.path, tag.host', '[{"type":"deepflow","tableName":"deepflow_server_monitor_disk","dbName":"deepflow_admin","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.used_percent","METRIC_NAME":"metrics.used_percent","isTimeUnit":false,"type":1,"unit":"","cascaderLabel":"metrics.free","display_name":"--","hasDerivative":false,"isPrometheus":false,"operatorLv2":[],"operatorLv1":"Last","perOperator":"","METRIC_LABEL":"disk_used_percent","checked":true,"percentile":null,"_key":"561bf802-10ae-4988-38f5-97001e896d8e","markLine":null,"ORIGIN_METRIC_LABEL":"Last(metrics.used_percent)"}],"dataSource":"","condition":{"dbName":"deepflow_admin","tableName":"deepflow_server_monitor_disk","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.host","tag.host_ip","tag.path"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.host","tag.host_ip","tag.path"]},"inputMode":"free"}]}}]',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_admin","TABLE":"deepflow_server_monitor_disk","interval":60,"fill": "none","window_size":1,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Last(`metrics.used_percent`) AS `disk_used_percent`","WHERE":"1=1","GROUP_BY":"`tag.host_ip`, `tag.path`, `tag.host`","METRICS":["Last(`metrics.used_percent`) AS `disk_used_percent`"]}]}' ,
    '[{"METRIC_LABEL":"disk_used_percent","return_field_description":"磁盘用量百分比","unit":"%"}]', '数据节点磁盘空间不足', 0, 1, 1, 21, 1, '', '', '{"displayName":"disk_used_percent", "unit": "%"}', '{"OP":">=","VALUE":70}', gen_random_uuid());

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: tag.host, tag.db, tag.table, tag.partition', '[{"type":"deepflow","tableName":"deepflow_server_ingester_force_delete_clickhouse_data","dbName":"deepflow_admin","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.bytes_on_disk","METRIC_NAME":"metrics.bytes_on_disk","isTimeUnit":false,"type":1,"unit":"","cascaderLabel":"metrics.bytes_on_disk","display_name":"--","hasDerivative":false,"isPrometheus":false,"operatorLv2":[],"operatorLv1":"Sum","perOperator":"","METRIC_LABEL":"force_delete_clickhouse_data_bytes_on_disk","checked":true,"percentile":null,"_key":"789ba080-5a52-11ad-25ae-097318b21194","markLine":null,"ORIGIN_METRIC_LABEL":"Sum(metrics.bytes_on_disk)"}],"dataSource":"","condition":{"dbName":"deepflow_admin","tableName":"deepflow_server_ingester_force_delete_clickhouse_data","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.host","tag.db","tag.partition","tag.table"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.host","tag.db","tag.partition","tag.table"]},"inputMode":"free"}]}}]',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_admin","TABLE":"deepflow_server_ingester_force_delete_clickhouse_data","interval":60,"fill": "none","window_size":1,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Sum(`metrics.bytes_on_disk`) AS `force_delete_clickhouse_data_bytes_on_disk`","WHERE":"1=1","GROUP_BY":"`tag.host`, `tag.db`, `tag.table`, `tag.partition`","METRICS":["Sum(`metrics.bytes_on_disk`) AS `force_delete_clickhouse_data_bytes_on_disk`"]}]}' ,
    '[{"METRIC_LABEL":"force_delete_clickhouse_data_bytes_on_disk","return_field_description":"最近 1 分钟数据节点数据强制删除","unit":"字节"}]', '数据节点数据强制删除', 0, 1, 1, 21, 1, '', '', '{"displayName":"force_delete_clickhouse_data_bytes_on_disk", "unit": "字节"}', '{"OP":">=","VALUE":1}', gen_random_uuid());

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: tag.host', '[{"type":"deepflow","tableName":"deepflow_server_ingester_recviver","dbName":"deepflow_admin","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.invalid","METRIC_NAME":"metrics.invalid","isTimeUnit":false,"type":1,"unit":"","checked":true,"operatorLv2":[],"_key":"2dfe0af2-b363-95b9-f8ce-acd3e9f0f567","perOperator":"","operatorLv1":"Sum","percentile":null,"markLine":null,"METRIC_LABEL":"ingester.recviver.metrics.invalid","ORIGIN_METRIC_LABEL":"Sum(metrics.invalid)"}],"dataSource":"","condition":{"dbName":"deepflow_admin","tableName":"deepflow_server_ingester_recviver","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.host"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.host"]},"inputMode":"free"}]}}]',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_admin","TABLE":"deepflow_server_ingester_recviver","interval":60,"fill": "none","window_size":1,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Sum(`metrics.invalid`) AS `ingester.recviver.metrics.invalid`","WHERE":"1=1","GROUP_BY":"`tag.host`","METRICS":["Sum(`metrics.invalid`) AS `ingester.recviver.metrics.invalid`"]}]}' ,
    '[{"METRIC_LABEL":"rx_drop_packets","return_field_description":"最近 1 分钟 ingester.recviver.metrics.invalid","unit":""}]', '数据节点数据丢失 (ingester.recviver.metrics.invalid)', 0, 1, 1, 21, 1, '', '', '{"displayName":"ingester.recviver.metrics.invalid", "unit": ""}', '{"OP":">=","VALUE":1}', gen_random_uuid());

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: tag.host, tag.module', '[{"type":"deepflow","tableName":"deepflow_server_ingester_queue","dbName":"deepflow_admin","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.overwritten","METRIC_NAME":"metrics.overwritten","isTimeUnit":false,"type":1,"unit":"","cascaderLabel":"metrics.in","display_name":"--","hasDerivative":false,"isPrometheus":false,"operatorLv2":[],"operatorLv1":"Sum","perOperator":"","METRIC_LABEL":"ingester.queue.metrics.overwritten","checked":true,"percentile":null,"_key":"e3554a5e-ec69-abe7-2c94-a5000578c23a","markLine":null,"ORIGIN_METRIC_LABEL":"Sum(metrics.overwritten)"}],"dataSource":"","condition":{"dbName":"deepflow_admin","tableName":"deepflow_server_ingester_queue","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.host","tag.module"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.host","tag.module"]},"inputMode":"free"}]}}]',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_admin","TABLE":"deepflow_server_ingester_queue","interval":60,"fill": "none","window_size":1,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Sum(`metrics.overwritten`) AS `ingester.queue.metrics.overwritten`","WHERE":"1=1","GROUP_BY":"`tag.host`, `tag.module`","METRICS":["Sum(`metrics.overwritten`) AS `ingester.queue.metrics.overwritten`"]}]}' ,
    '[{"METRIC_LABEL":"rx_drop_packets","return_field_description":"最近 1 分钟 ingester.queue.metrics.overwritten","unit":""}]', '数据节点数据丢失 (ingester.queue.metrics.overwritten)', 0, 1, 1, 21, 1, '', '', '{"displayName":"ingester.queue.metrics.overwritten", "unit": ""}', '{"OP":">=","VALUE":1}', gen_random_uuid());

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: tag.host', '[{"type":"deepflow","tableName":"deepflow_server_ingester_decoder","dbName":"deepflow_admin","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.drop_count","METRIC_NAME":"metrics.drop_count","isTimeUnit":false,"type":1,"unit":"","cascaderLabel":"metrics.avg_time","display_name":"--","hasDerivative":false,"isPrometheus":false,"operatorLv2":[],"operatorLv1":"Sum","perOperator":"","METRIC_LABEL":"ingester.decoder.metrics.drop_count","checked":true,"percentile":null,"_key":"3c32775e-72b5-a62c-c97d-b90bdf049923","markLine":null,"ORIGIN_METRIC_LABEL":"Sum(metrics.drop_count)"}],"dataSource":"","condition":{"dbName":"deepflow_admin","tableName":"deepflow_server_ingester_decoder","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.host"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.host"]},"inputMode":"free"}]}}]',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_admin","TABLE":"deepflow_server_ingester_decoder","interval":60,"fill": "none","window_size":1,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Sum(`metrics.drop_count`) AS `ingester.decoder.metrics.drop_count`","WHERE":"1=1","GROUP_BY":"`tag.host`","METRICS":["Sum(`metrics.drop_count`) AS `ingester.decoder.metrics.drop_count`"]}]}' ,
    '[{"METRIC_LABEL":"rx_drop_packets","return_field_description":"最近 1 分钟 ingester.decoder.metrics.drop_count","unit":""}]', '数据节点数据丢失 (ingester.decoder.metrics.drop_count)', 0, 1, 1, 21, 1, '', '', '{"displayName":"ingester.decoder.metrics.drop_count", "unit": ""}', '{"OP":">=","VALUE":1}', gen_random_uuid());

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    threshold_warning, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: tag.host', '[{"type":"deepflow","tableName":"deepflow_server_ingester_ckwriter","dbName":"deepflow_admin","metrics":[{"description":"","typeName":"counter","METRIC_CATEGORY":"metrics","METRIC":"metrics.write_failed_count","METRIC_NAME":"metrics.write_failed_count","isTimeUnit":false,"type":1,"unit":"","cascaderLabel":"metrics.org_invalid_count","display_name":"--","hasDerivative":false,"isPrometheus":false,"operatorLv2":[],"operatorLv1":"Sum","perOperator":"","METRIC_LABEL":"ingester.ckwriter.metrics.write_failed_count","checked":true,"percentile":null,"_key":"14090ba1-13b7-97eb-de89-a141e06afc89","markLine":null,"ORIGIN_METRIC_LABEL":"Sum(metrics.write_failed_count)"}],"dataSource":"","condition":{"dbName":"deepflow_admin","tableName":"deepflow_server_ingester_ckwriter","type":"simplified","RESOURCE_SETS":[{"id":"R1","condition":[],"groupBy":["_","tag.host"],"groupInfo":{"mainGroupInfo":["_"],"otherGroupInfo":["tag.host"]},"inputMode":"free"}]}}]',
    '/v1/stats/querier/UniversalHistory', '{"DATABASE":"deepflow_admin","TABLE":"deepflow_server_ingester_ckwriter","interval":60,"fill": "none","window_size":1,"QUERIES":[{"QUERY_ID":"R1","SELECT":"Sum(`metrics.write_failed_count`) AS `ingester.ckwriter.metrics.write_failed_count`","WHERE":"1=1","GROUP_BY":"`tag.host`","METRICS":["Sum(`metrics.write_failed_count`) AS `ingester.ckwriter.metrics.write_failed_count`"]}]}' ,
    '[{"METRIC_LABEL":"rx_drop_packets","return_field_description":"最近 1 分钟 ingester.ckwriter.metrics.write_failed_count","unit":""}]', '数据节点数据丢失 (ingester.ckwriter.metrics.write_failed_count)', 0, 1, 1, 21, 1, '', '', '{"displayName":"ingester.ckwriter.metrics.write_failed_count", "unit": ""}', '{"OP":">=","VALUE":1}', gen_random_uuid());

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field, data_level, agg, delay,
    threshold_error, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: *', '', '/v1/alarm/voucher-30days/', '{}', '[{"OPERATOR": {"return_field": "sysalarm_value", "return_field_description": "余额预估可用天数", "return_field_unit": "天"}}]', 'DeepFlow 服务即将停止', 1, 1, 1, 24, 1, '', '', '{"displayName":"sysalarm_value", "unit": "天"}', '1d', 1, 0, '{"OP":"<=", "VALUE":30}', gen_random_uuid());

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field, data_level, agg, delay,
    threshold_critical, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: *', '', '/v1/alarm/voucher-0days/', '{}', '[{"OPERATOR": {"return_field": "sysalarm_value", "return_field_description": "余额可用天数", "return_field_unit": "天"}}]', 'DeepFlow 服务停止', 2, 1, 1, 24, 1, '', '', '{"displayName":"sysalarm_value", "unit": "天"}', '1d', 1, 0, '{"OP":"<=", "VALUE":0}', gen_random_uuid());

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field, data_level, agg, delay,
    threshold_error, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: *', '', '/v1/alarm/license-30days/', '{}', '[{"OPERATOR": {"return_field": "sysalarm_value", "return_field_description": "至少一个授权文件剩余有效期", "return_field_unit": "天"}}]', 'DeepFlow 授权即将过期', 1, 1, 1, 24, 1, '', '', '{"displayName":"sysalarm_value", "unit": "天"}', '1d', 1, 0, '{"OP":"<=", "VALUE":30}', gen_random_uuid());

INSERT INTO alarm_policy (
    user_id, sub_view_type, tag_conditions, query_conditions, query_url, query_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field, data_level, agg, delay,
    threshold_critical, lcuuid)
VALUES (
    1, 1, '过滤项: N/A | 分组项: *', '', '/v1/alarm/license-0days/', '{}', '[{"OPERATOR": {"return_field": "sysalarm_value", "return_field_description": "至少一个授权文件剩余有效期", "return_field_unit": "天"}}]', 'DeepFlow 授权过期', 2, 1, 1, 24, 1, '', '', '{"displayName":"sysalarm_value", "unit": "天"}', '1d', 1, 0, '{"OP":"<=", "VALUE":0}', gen_random_uuid());

-- 重新设置序列起始值，避免主键冲突
SELECT setval('data_source_id_seq', (SELECT max(id) FROM data_source));
INSERT INTO data_source (display_name, data_table_collection, interval_time, retention_time, lcuuid)
VALUES ('管理侧监控数据', 'deepflow_admin.*', 0, 7*24, gen_random_uuid());
