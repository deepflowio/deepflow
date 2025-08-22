-- modify start, add upgrade sql
DROP PROCEDURE IF EXISTS update_data_sources;

CREATE PROCEDURE update_data_sources()
BEGIN
    DECLARE current_db_name VARCHAR(255);
    
    START TRANSACTION;

    UPDATE alarm_policy SET monitoring_interval="5m"  WHERE name="采集器 CPU 超限";
    UPDATE alarm_policy SET monitoring_interval="5m" WHERE name="采集器内存超限";
    UPDATE alarm_policy SET monitoring_interval="5m", query_params="{\"DATABASE\":\"deepflow_tenant\",\"TABLE\":\"deepflow_agent_monitor\",\"interval\":60,\"fill\": \"none\",\"window_size\":5,\"QUERIES\":[{\"QUERY_ID\":\"R1\",\"SELECT\":\"Min(`metrics.sys_free_memory_limit_ratio`)*100 AS `used_bytes`\",\"WHERE\":\"`metrics.sys_free_memory_limit_ratio`!=0\",\"GROUP_BY\":\"`tag.host`\",\"METRICS\":[\"Min(`metrics.sys_free_memory_limit_ratio`)*100 AS `used_bytes`\"]}]}" WHERE name="采集器所在系统空闲内存低";

    -- do migration in default db
    
    SELECT DATABASE() INTO current_db_name;
    IF @defaultDatabaseName = current_db_name THEN
        UPDATE alarm_policy SET monitoring_interval="5m", tag_conditions="过滤项: N/A | 分组项: tag.host_ip, tag.host" WHERE name="控制器系统负载高";
        UPDATE alarm_policy SET monitoring_interval="5m", tag_conditions="过滤项: N/A | 分组项: tag.host_ip, tag.host" WHERE name="数据节点系统负载高";
    END IF;
    COMMIT; 

END;

CALL update_data_sources();

-- whether default db or not, update db_version to latest, remember update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.6.1.1';
-- modify end
