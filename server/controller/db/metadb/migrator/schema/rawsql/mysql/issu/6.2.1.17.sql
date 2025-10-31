DROP PROCEDURE IF EXISTS update_data_sources;

CREATE PROCEDURE update_data_sources()
BEGIN
    DECLARE existing_name INT DEFAULT 0;

    SELECT COUNT(*) INTO existing_name
    FROM data_source
    WHERE name = 'flow_log.l4_packet';

    IF existing_name = 0 THEN
        START TRANSACTION;

        UPDATE data_source SET retention_time = retention_time * 24;
        UPDATE data_source SET name="flow_log.l4_flow_log", tsdb_type="flow_log.l4_flow_log" WHERE name="flow_log.l4";
        UPDATE data_source SET name="flow_log.l7_flow_log", tsdb_type="flow_log.l7_flow_log" WHERE name="flow_log.l7";

        SET @lcuuid = (SELECT UUID());
        INSERT INTO data_source (name, tsdb_type, `interval`, retention_time, lcuuid) VALUES ('flow_log.l4_packet', 'flow_log.l4_packet', 0, 3*24, @lcuuid);
        SET @lcuuid = (SELECT UUID());
        INSERT INTO data_source (name, tsdb_type, `interval`, retention_time, lcuuid) VALUES ('flow_log.l7_packet', 'flow_log.l7_packet', 0, 3*24, @lcuuid);
        SET @lcuuid = (SELECT UUID());
        INSERT INTO data_source (name, tsdb_type, `interval`, retention_time, lcuuid) VALUES ('deepflow_system', 'deepflow_system', 0, 3*24, @lcuuid);

        COMMIT;
    END IF;

    UPDATE db_version SET version = '6.2.1.17';
END;

CALL update_data_sources();
