START TRANSACTION;

UPDATE alarm_policy SET sub_view_metrics="[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 flow_aggr.metrics.drop-before-window\",\"unit\":\"\"}]"  WHERE name="采集器数据丢失 (flow_aggr.metrics.drop-before-window)";
UPDATE alarm_policy SET sub_view_metrics="[{\"METRIC_LABEL\":\"drop_packets\",\"return_field_description\":\"最近 1 分钟 collect_sender.metrics.dropped\",\"unit\":\"\"}]" WHERE name="采集器数据丢失 (collect_sender.metrics.dropped)";


-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.3.1.32';
-- modify end

COMMIT;
