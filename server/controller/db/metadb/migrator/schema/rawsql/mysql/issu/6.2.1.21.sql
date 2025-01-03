START TRANSACTION;

-- modify start, add upgrade sql

UPDATE alarm_policy SET sub_view_url="/v1/stats/querier/UniversalHistory", user_id=1 WHERE name="控制器负载高";

UPDATE alarm_policy SET sub_view_url="/v1/stats/querier/UniversalHistory", user_id=1 WHERE name="数据节点负载高";

UPDATE alarm_policy SET sub_view_url="/v1/stats/querier/UniversalHistory", user_id=1 WHERE name="控制器磁盘空间不足";

UPDATE alarm_policy SET sub_view_url="/v1/stats/querier/UniversalHistory", user_id=1 WHERE name="数据节点磁盘空间不足";

UPDATE alarm_policy SET sub_view_url="/v1/stats/querier/UniversalHistory", user_id=1 WHERE name="采集器CPU超限";

UPDATE alarm_policy SET sub_view_url="/v1/stats/querier/UniversalHistory", user_id=1 WHERE name="采集器内存超限";

UPDATE alarm_policy SET sub_view_url="/v1/stats/querier/UniversalHistory", user_id=1 WHERE name="数据节点写入失败";

UPDATE alarm_policy SET sub_view_url="/v1/stats/querier/UniversalHistory", user_id=1 WHERE name="采集器系统空闲内存比例超限";

UPDATE alarm_policy SET sub_view_url="/v1/stats/querier/UniversalHistory", user_id=1 WHERE name="采集器的WARN日志条数超限";

UPDATE alarm_policy SET sub_view_url="/v1/stats/querier/UniversalHistory", user_id=1 WHERE name="采集器的ERR日志条数超限";

UPDATE alarm_policy SET sub_view_url="/v1/stats/querier/UniversalHistory", user_id=1 WHERE name="K8s容器信息同步滞后";

UPDATE alarm_policy SET sub_view_url="/v1/stats/querier/UniversalHistory", user_id=1 WHERE name="采集器丢包(dispatcher)";

UPDATE alarm_policy SET sub_view_url="/v1/stats/querier/UniversalHistory", user_id=1 WHERE name="采集器丢包(queue)";

UPDATE alarm_policy SET sub_view_url="/v1/stats/querier/UniversalHistory", user_id=1 WHERE name="采集器丢包(l7_session_aggr)";

UPDATE alarm_policy SET sub_view_url="/v1/stats/querier/UniversalHistory", user_id=1 WHERE name="采集器丢包(flow_aggr)";

UPDATE alarm_policy SET sub_view_url="/v1/stats/querier/UniversalHistory", user_id=1 WHERE name="数据节点丢包(ingester.recviver)";

UPDATE alarm_policy SET sub_view_url="/v1/stats/querier/UniversalHistory", user_id=1 WHERE name="数据节点丢包(ingester.trident_adapter)";

UPDATE alarm_policy SET sub_view_url="/v1/stats/querier/UniversalHistory", user_id=1 WHERE name="数据节点丢包(ingester.queue)";

UPDATE alarm_policy SET sub_view_url="/v1/stats/querier/UniversalHistory", user_id=1 WHERE name="数据节点丢包(ingester.decoder.drop_count)";

UPDATE alarm_policy SET sub_view_url="/v1/stats/querier/UniversalHistory", user_id=1 WHERE name="数据节点丢包(ingester.decoder.l7_dns_drop_count)";

UPDATE alarm_policy SET sub_view_url="/v1/stats/querier/UniversalHistory", user_id=1 WHERE name="数据节点丢包(ingester.decoder.l7_http_drop_count)";


-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.2.1.21';
-- modify end

COMMIT;