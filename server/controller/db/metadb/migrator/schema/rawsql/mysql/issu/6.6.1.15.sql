-- modify start, add upgrade sql
DROP PROCEDURE IF EXISTS insert_data_source;

CREATE PROCEDURE insert_data_source(
    IN DisplayName CHAR(64),
    IN DataTableCollection CHAR(64),
    IN DataInterval INT
)
BEGIN
    DECLARE existing_display_name INT DEFAULT 0;
    DECLARE existing_base_data_source_id INT DEFAULT 0;

    SELECT COUNT(*) INTO existing_display_name
    FROM data_source
    WHERE data_table_collection = DataTableCollection
        AND `interval` = DataInterval;

    -- check base data_source
    -- if not exist, exit current sql
    IF DataInterval = 3600 THEN
        SELECT id INTO existing_base_data_source_id
        FROM data_source
        WHERE  data_table_collection = DataTableCollection
            AND `interval` = 60;
    ELSE
        SELECT id INTO existing_base_data_source_id
        FROM data_source
        WHERE  data_table_collection = DataTableCollection
            AND `interval` = 3600;
    END IF;

    IF existing_base_data_source_id = 0 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'data_source with interval 3600/86400 not exist';
    END IF;

    IF existing_display_name = 0 THEN
        START TRANSACTION;

        SET @lcuuid = (SELECT UUID());
        INSERT INTO data_source (display_name, data_table_collection, base_data_source_id, `interval`, retention_time, summable_metrics_operator, unsummable_metrics_operator, lcuuid)
        VALUES (DisplayName, DataTableCollection, existing_base_data_source_id, DataInterval, 30*24, 'Sum', 'Avg', @lcuuid);

        COMMIT; 
    END IF;

END;

CALL insert_data_source('网络-指标（小时级）', 'flow_metrics.network*', 3600);
CALL insert_data_source('网络-指标（天级）', 'flow_metrics.network*', 86400);
CALL insert_data_source('应用-指标（小时级）', 'flow_metrics.application*', 3600);
CALL insert_data_source('应用-指标（天级）', 'flow_metrics.application*', 86400);

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.6.1.15';
-- modify end
