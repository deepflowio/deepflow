DROP PROCEDURE IF EXISTS HardDeleteConfigMaps;

CREATE PROCEDURE HardDeleteConfigMaps()
BEGIN
    DECLARE batch_size INT DEFAULT 100000;
    DECLARE deleted_count INT DEFAULT 1;
    
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
END;

CALL HardDeleteConfigMaps();
DROP PROCEDURE HardDeleteConfigMaps;

UPDATE db_version SET version='7.1.0.12';