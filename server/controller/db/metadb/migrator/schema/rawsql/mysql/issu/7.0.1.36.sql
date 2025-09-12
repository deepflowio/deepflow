DROP PROCEDURE IF EXISTS insert_data_source;

CREATE PROCEDURE insert_data_source()
BEGIN
    DECLARE existing_display_name INT DEFAULT 0;

    SELECT COUNT(*) INTO existing_display_name
    FROM data_source
    WHERE  display_name = '事件-IO 事件指标';

    IF existing_display_name = 0 THEN
        START TRANSACTION;
        set @lcuuid = (select uuid());
        INSERT INTO data_source (display_name, data_table_collection, `interval_time`, retention_time, summable_metrics_operator, unsummable_metrics_operator, lcuuid)
        VALUES ('事件-IO 事件指标', 'event.file_event_metrics', 1, 7*24, 'Sum', 'Avg', @lcuuid);
        COMMIT; 
    END IF;

END;

CALL insert_data_source();
DROP PROCEDURE insert_data_source;

UPDATE db_version SET version='7.0.1.36';
