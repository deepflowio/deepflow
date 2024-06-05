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
    END IF;

    COMMIT; 

END;

CALL update_data_sources();

-- whether default db or not, update db_version to latest, remember update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.5.1.42';
-- modify end
