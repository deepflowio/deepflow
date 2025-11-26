DROP PROCEDURE IF EXISTS HardDeleteConfigMaps;

CREATE PROCEDURE HardDeleteConfigMaps()
BEGIN
    DECLARE batch_size INT DEFAULT 100000;
    DECLARE deleted_count INT DEFAULT 1;
    
    -- check if there is deleted_at field in config_map table
    DECLARE column_count INT;

    SELECT COUNT(*)
    INTO column_count
    FROM information_schema.columns
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'config_map'
    AND column_name = 'deleted_at';

    IF column_count > 0 THEN
        WHILE deleted_count > 0 DO
            DELETE FROM config_map 
            WHERE deleted_at IS NOT NULL 
            LIMIT batch_size;
            
            SET deleted_count = ROW_COUNT();
            
            -- 可选：添加延迟减少系统负载
            DO SLEEP(0.1);
            
            -- 可选：显示进度（在支持 SELECT 输出的环境中）
            SELECT CONCAT('Deleted ', deleted_count, ' records in this batch') AS progress;
        END WHILE;

        ALTER TABLE config_map CHANGE deleted_at deleted_at_backup DATETIME DEFAULT NULL;

    END IF;

END;

CALL HardDeleteConfigMaps();
DROP PROCEDURE HardDeleteConfigMaps;

UPDATE db_version SET version='7.1.0.12';