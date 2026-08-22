DROP PROCEDURE IF EXISTS InsertDataSourceIfNotExists;

CREATE PROCEDURE InsertDataSourceIfNotExists(
    IN p_display_name VARCHAR(64),
    IN p_data_table_collection VARCHAR(64),
    IN p_interval_time INTEGER,
    IN p_retention_time INTEGER
)
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM data_source
        WHERE data_table_collection = p_data_table_collection
    ) THEN
        INSERT INTO data_source (
            display_name,
            data_table_collection,
            base_data_source_id,
            interval_time,
            retention_time,
            lcuuid
        )
        VALUES (
            p_display_name,
            p_data_table_collection,
            0,
            p_interval_time,
            p_retention_time,
            UUID()
        );
    END IF;
END;

CALL InsertDataSourceIfNotExists('事件-进程阻断事件', 'event.proc_block_event', 0, 7*24);

DROP PROCEDURE InsertDataSourceIfNotExists;

UPDATE db_version SET version='7.1.0.41';
