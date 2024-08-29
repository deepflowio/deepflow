DROP PROCEDURE IF EXISTS check_data_sources;

CREATE PROCEDURE check_data_sources()
BEGIN
    START TRANSACTION;
    -- check if it is possible to upgrade
    -- the value of data_source.name must be in ('1h', '1d', '1s', '1m', 'flow_log.l4_flow_log', 'flow_log.l7_flow_log', 
    -- 'flow_log.l4_packet', 'flow_log.l7_packet', 'deepflow_system')
    IF EXISTS (
        SELECT 1
        FROM data_source
        WHERE name NOT IN ('1h', '1d', '1s', '1m', 'flow_log.l4_flow_log', 'flow_log.l7_flow_log', 'flow_log.l4_packet', 'flow_log.l7_packet', 'deepflow_system')
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'invalid name for data_source to upgrade, please delete custom data_source';
    END IF;

    UPDATE data_source SET retention_time =  3* 24 WHERE name='deepflow_system';
    UPDATE data_source SET name='网络-指标（秒级）', tsdb_type='flow_metrics.vtap_flow*' WHERE id=1;
    UPDATE data_source SET name='网络-指标（分钟级）', tsdb_type='flow_metrics.vtap_flow*' WHERE id=3;
    UPDATE data_source SET name='网络-流日志' WHERE id=6;
    UPDATE data_source SET name='应用-指标（秒级）', tsdb_type='flow_metrics.vtap_app*' WHERE id=7;
    UPDATE data_source SET name='应用-指标（分钟级）', tsdb_type='flow_metrics.vtap_app*' WHERE id=8;
    UPDATE data_source SET name='应用-调用日志' WHERE id=9;
    UPDATE data_source SET name='网络-TCP 时序数据' WHERE name='flow_log.l4_packet' AND tsdb_type='flow_log.l4_packet';
    UPDATE data_source SET name='网络-PCAP 数据' WHERE name='flow_log.l7_packet' AND tsdb_type='flow_log.l7_packet';
    UPDATE data_source SET name='系统监控数据', tsdb_type='deepflow_system.*' WHERE name='deepflow_system' AND tsdb_type='deepflow_system';

    ALTER TABLE data_source CHANGE COLUMN name display_name CHAR(64);
    ALTER TABLE data_source CHANGE COLUMN tsdb_type data_table_collection CHAR(64);

    set @lcuuid = (select uuid());
    INSERT INTO data_source (display_name, data_table_collection, `interval`, retention_time, lcuuid) 
                 VALUES ('外部指标数据', 'ext_metrics.*', 0, 7*24, @lcuuid);
    set @lcuuid = (select uuid());
    INSERT INTO data_source (display_name, data_table_collection, `interval`, retention_time, lcuuid) 
                 VALUES ('Prometheus 数据', 'prometheus.*', 0, 7*24, @lcuuid); 
    set @lcuuid = (select uuid());
    INSERT INTO data_source (display_name, data_table_collection, `interval`, retention_time, lcuuid) 
                 VALUES ('事件-资源变更事件', 'event.event', 0, 3*24, @lcuuid);
    set @lcuuid = (select uuid());
    INSERT INTO data_source (display_name, data_table_collection, `interval`, retention_time, lcuuid) 
                 VALUES ('事件-IO 事件', 'event.perf_event', 0, 3*24, @lcuuid);
    set @lcuuid = (select uuid());
    INSERT INTO data_source (display_name, data_table_collection, `interval`, retention_time, lcuuid) 
                 VALUES ('事件-告警事件', 'event.alarm_event', 0, 3*24, @lcuuid);
 
    UPDATE db_version SET version='6.3.1.38';
    COMMIT;
END;

CALL check_data_sources();
