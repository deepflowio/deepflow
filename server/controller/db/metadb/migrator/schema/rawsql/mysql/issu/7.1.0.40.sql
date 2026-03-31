DROP PROCEDURE IF EXISTS AddColumnIfNotExists;
DROP PROCEDURE IF EXISTS InsertDataSourceIfNotExists;

CREATE PROCEDURE AddColumnIfNotExists(
    IN tableName VARCHAR(255),
    IN colName VARCHAR(255),
    IN colType VARCHAR(255),
    IN afterCol VARCHAR(255)
)
BEGIN
    DECLARE column_count INT;

    SELECT COUNT(*)
    INTO column_count
    FROM information_schema.columns
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = tableName
    AND column_name = colName;

    IF column_count = 0 THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' ADD COLUMN ', colName, ' ', colType, ' AFTER ', afterCol);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

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

CALL AddColumnIfNotExists('process', 'biz_type', 'INTEGER DEFAULT 0', 'process_name');
CALL AddColumnIfNotExists('genesis_process', 'biz_type', 'INTEGER DEFAULT 0', 'process_name');
CALL AddColumnIfNotExists('ch_gprocess', 'biz_type', 'INTEGER DEFAULT 0', 'l3_epc_id');

CALL InsertDataSourceIfNotExists('事件-文件读写聚合事件', 'event.file_agg_event', 0, 7*24);
CALL InsertDataSourceIfNotExists('事件-文件管理事件', 'event.file_mgmt_event', 0, 7*24);
CALL InsertDataSourceIfNotExists('事件-进程权限事件', 'event.proc_perm_event', 0, 7*24);
CALL InsertDataSourceIfNotExists('事件-进程操作事件', 'event.proc_ops_event', 0, 7*24);

DROP PROCEDURE AddColumnIfNotExists;
DROP PROCEDURE InsertDataSourceIfNotExists;

UPDATE db_version SET version='7.1.0.40';
