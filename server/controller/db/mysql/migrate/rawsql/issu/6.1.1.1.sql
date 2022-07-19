/* TODO rolling issu */
USE deepflow;

ALTER TABLE vtap_group_configuration
    ADD COLUMN inactive_ip_enabled       TINYINT(1) COMMENT '0: disabled 1:enabled';

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/alarm/vtap-logcount-warning/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"WARN日志条数1分钟总量\", \"return_field_unit\": \"条\"}}]", "采集器的WARN日志条数超限",  0, 1, 1, 20, 1, "", "", "sysalarm_value", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/alarm/vtap-logcount-error/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"ERR日志条数1分钟总量\", \"return_field_unit\": \"条\"}}]", "采集器的ERR日志条数超限",  0, 1, 1, 20, 1, "", "", "sysalarm_value", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/alarm/sync-k8sinfo-delay/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"同步滞后时间\", \"return_field_unit\": \"秒\"}}]", "K8s容器信息同步滞后",  0, 1, 1, 23, 1, "", "", "sysalarm_value", 600, NULL, @lcuuid);
