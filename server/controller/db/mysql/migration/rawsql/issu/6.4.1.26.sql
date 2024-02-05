DROP PROCEDURE IF EXISTS update_data_sources;

CREATE PROCEDURE update_data_sources()
BEGIN
    DECLARE existing_display_name INT DEFAULT 0;

    SELECT COUNT(*) INTO existing_display_name
    FROM data_source
    WHERE display_name = '网络策略';

    IF existing_display_name = 0 THEN
        START TRANSACTION;

        SET @lcuuid = (SELECT UUID());
        INSERT INTO data_source (display_name, data_table_collection, `interval`, retention_time, lcuuid) VALUES ('网络策略', 'flow_metrics.vtap_acl', 60, 3*24, @lcuuid);

        UPDATE db_version SET version = '6.4.1.26';

        COMMIT;
    END IF;
END;

CALL update_data_sources();
