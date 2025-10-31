-- modify start, add upgrade sql
DROP PROCEDURE IF EXISTS update_data_sources;

CREATE PROCEDURE update_data_sources()
BEGIN
    DECLARE existing_display_name INT DEFAULT 0;

    SELECT COUNT(*) INTO existing_display_name
    FROM data_source
    WHERE display_name = '日志数据';

    IF existing_display_name = 0 THEN
        START TRANSACTION;

        SET @lcuuid = (SELECT UUID());
        INSERT INTO data_source (display_name, data_table_collection, `interval`, retention_time, lcuuid) VALUES ('日志数据', 'application_log.log', 1, 7*24, @lcuuid);

        COMMIT; 
    END IF;

END;

CALL update_data_sources();

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.5.1.33';
-- modify end
