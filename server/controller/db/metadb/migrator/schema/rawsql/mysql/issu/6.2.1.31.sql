START TRANSACTION;

-- modify start, add upgrade sql

UPDATE alarm_policy SET sub_view_metrics="[{\"METRIC_LABEL\":\"rx_drop_packets\",\"return_field_description\":\"最近 1 分钟 ingester.ckwriter.metrics.write_failed_count\",\"unit\":\"\"}]" WHERE name="数据节点数据丢失 (ingester.ckwriter.metrics.write_failed_count)";

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.2.1.31';
-- modify end

COMMIT;