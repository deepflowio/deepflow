START TRANSACTION;

-- modify start, add upgrade sql

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server_monitor\",\"interval\":60,\"fill\": \"none\",\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Min(`metrics.load1`*100/`metrics.cpu_num`) AS `load`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host_ip`, `tag.host`\",\"METRICS\":[\"Min(`metrics.load1`*100/`metrics.cpu_num`) AS `load`\"]}]}" WHERE name="控制器系统负载高";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server_monitor\",\"interval\":60,\"fill\": \"none\",\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Min(`metrics.load1`*100/`metrics.cpu_num`) AS `load`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host_ip`, `tag.host`\",\"METRICS\":[\"Min(`metrics.load1`*100/`metrics.cpu_num`) AS `load`\"]}]}" WHERE name="数据节点系统负载高";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server_ingester_recviver\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.invalid`) AS `rx_drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.invalid`) AS `rx_drop_packets`\"]}]}" WHERE name="数据节点数据丢失 (ingester.recviver.metrics.invalid)";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server_ingester_queue\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.overwritten`) AS `rx_drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.overwritten`) AS `rx_drop_packets`\"]}]}" WHERE name="数据节点数据丢失 (ingester.queue.metrics.overwritten)";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server_ingester_decoder\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.drop_count`) AS `rx_drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.drop_count`) AS `rx_drop_packets`\"]}]}" WHERE name="数据节点数据丢失 (ingester.decoder.metrics.drop_count)";

UPDATE alarm_policy SET query_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server_ingester_ckwriter\",\"interval\":60,\"fill\": \"none\",\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.write_failed_count`) AS `rx_drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.write_failed_count`) AS `rx_drop_packets`\"]}]}" WHERE name="数据节点数据丢失 (ingester.ckwriter.metrics.write_failed_count)";

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.4.1.21';
-- modify end

COMMIT;
