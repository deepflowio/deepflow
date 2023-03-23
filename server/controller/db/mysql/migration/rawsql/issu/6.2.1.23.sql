START TRANSACTION;

-- modify start, add upgrade sql


UPDATE alarm_policy SET sub_view_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_dispatcher\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.kernel_drops`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.kernel_drops`) AS `drop_packets`\"]}]}" WHERE name="采集器丢包(dispatcher)";

UPDATE alarm_policy SET sub_view_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_queue\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.overwritten`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.overwritten`) AS `drop_packets`\"]}]}" WHERE name="采集器丢包(queue)";

UPDATE alarm_policy SET sub_view_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_l7_session_aggr\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.throttle-drop`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.throttle-drop`) AS `drop_packets`\"]}]}" WHERE name="采集器丢包(l7_session_aggr)";

UPDATE alarm_policy SET sub_view_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_agent_flow_aggr\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.drop-in-throttle`) AS `drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.drop-in-throttle`) AS `drop_packets`\"]}]}" WHERE name="采集器丢包(flow_aggr)";

UPDATE alarm_policy SET sub_view_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server.ingester.recviver\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.udp_dropped`) AS `rx_drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.udp_dropped`) AS `rx_drop_packets`\"]}]}" WHERE name="数据节点丢包(ingester.recviver)";

UPDATE alarm_policy SET sub_view_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server.ingester.trident_adapter\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.rx_dropped`) AS `rx_drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.rx_dropped`) AS `rx_drop_packets`\"]}]}" WHERE name="数据节点丢包(ingester.trident_adapter)";

UPDATE alarm_policy SET sub_view_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server.ingester.queue\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.overwritten`) AS `rx_drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.overwritten`) AS `rx_drop_packets`\"]}]}" WHERE name="数据节点丢包(ingester.queue)";

UPDATE alarm_policy SET sub_view_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server.ingester.decoder\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.drop_count`) AS `rx_drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.drop_count`) AS `rx_drop_packets`\"]}]}" WHERE name="数据节点丢包(ingester.decoder.drop_count)";

UPDATE alarm_policy SET sub_view_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server.ingester.decoder\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.l7_dns_drop_count`) AS `rx_drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.l7_dns_drop_count`) AS `rx_drop_packets`\"]}]}" WHERE name="数据节点丢包(ingester.decoder.l7_dns_drop_count)";

UPDATE alarm_policy SET sub_view_params="{\"DATABASE\":\"deepflow_system\",\"TABLE\":\"deepflow_server.ingester.decoder\",\"interval\":60,\"fill\":0,\"window_size\":1,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Sum(`metrics.l7_http_drop_count`) AS `rx_drop_packets`\",\"WHERE\":\"1=1\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Sum(`metrics.l7_http_drop_count`) AS `rx_drop_packets`\"]}]}" WHERE name="数据节点丢包(ingester.decoder.l7_http_drop_count)";


-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.2.1.23';
-- modify end

COMMIT;
