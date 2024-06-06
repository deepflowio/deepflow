-- modify start, add upgrade sql
DROP PROCEDURE IF EXISTS update_data_sources;

CREATE PROCEDURE update_data_sources()
BEGIN
    DECLARE current_db_name VARCHAR(255);
    
    START TRANSACTION;

    UPDATE data_source SET display_name='日志-日志数据',retention_time=720 WHERE data_table_collection='application_log.log';
    UPDATE data_source SET display_name='租户侧监控数据', data_table_collection='deepflow_tenant.*' WHERE data_table_collection='deepflow_system.*';

    -- do migration in default db
    
    SELECT DATABASE() INTO current_db_name;
    IF @defaultDatabaseName = current_db_name THEN
        IF NOT EXISTS (SELECT 1 FROM data_source WHERE data_table_collection = 'deepflow_admin.*') THEN
            SET @lcuuid = (SELECT UUID());
            INSERT INTO data_source (display_name, data_table_collection, `interval`, retention_time, lcuuid) 
            VALUES ('管理侧监控数据', 'deepflow_admin.*', 0, 7*24, @lcuuid);
        END IF;
        UPDATE alarm_policy SET query_params = REPLACE(query_params, 'deepflow_system', 'deepflow_admin') WHERE
        name in ("控制器磁盘空间不足", "控制器系统负载高", "数据节点系统负载高", "数据节点磁盘空间不足", "数据节点数据强制删除", "数据节点数据丢失 (ingester.recviver.metrics.invalid)", "数据节点数据丢失 (ingester.queue.metrics.overwritten)","数据节点数据丢失 (ingester.decoder.metrics.drop_count)", "数据节点数据丢失 (ingester.ckwriter.metrics.write_failed_count)");
    END IF;
    UPDATE alarm_policy SET query_params = REPLACE(query_params, 'deepflow_system', 'deepflow_tenant') WHERE
    name in ("采集器 CPU 超限", "采集器内存超限", "采集器重启", "采集器所在系统空闲内存低", "采集器 WARN 日志过多", "采集器 ERR 日志过多", "K8s 资源同步滞后", "采集器数据丢失 (dispatcher.metrics.kernel_drops)", "采集器数据丢失 (queue.metrics.overwritten)", "采集器数据丢失 (l7_session_aggr.metrics.throttle-drop)", "采集器数据丢失 (flow_aggr.metrics.drop-in-throttle)", "采集器数据丢失 (ebpf_collector.metrics.kern_lost)", "采集器数据丢失 (ebpf_collector.metrics.user_enqueue_lost)", "采集器数据丢失 (dispatcher.metrics.invalid_packets)", "采集器数据丢失 (dispatcher.metrics.err)", "采集器数据丢失 (flow_map.metrics.drop_by_window)", "采集器数据丢失 (flow_map.metrics.drop_by_capacity)", "采集器数据丢失 (flow_aggr.metrics.drop-before-window)", "采集器数据丢失 (quadruple_generator.metrics.drop-before-window)", "采集器数据丢失 (collector.metrics.drop-before-window)", "采集器数据丢失 (collector.metrics.drop-inactive)", "采集器数据丢失 (collect_sender.metrics.dropped)");
    COMMIT; 

END;

CALL update_data_sources();

-- whether default db or not, update db_version to latest, remember update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.5.1.42';
-- modify end
