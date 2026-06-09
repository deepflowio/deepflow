DROP PROCEDURE IF EXISTS AddIndexIfNotExists;

CREATE PROCEDURE AddIndexIfNotExists(
    IN tableName VARCHAR(255),
    IN indexName VARCHAR(255),
    IN indexCol  VARCHAR(255)
)
BEGIN
    DECLARE index_count INT;

    SELECT COUNT(*)
    INTO index_count
    FROM information_schema.statistics
    WHERE table_schema = DATABASE()
      AND table_name   = tableName
      AND column_name  = indexCol;

    IF index_count = 0 THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' ADD INDEX ', indexName, ' (', indexCol, ') USING BTREE');
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

CALL AddIndexIfNotExists('vm', 'created_at_index', 'created_at');
CALL AddIndexIfNotExists('lb', 'created_at_index', 'created_at');
CALL AddIndexIfNotExists('pod_group', 'created_at_index', 'created_at');
CALL AddIndexIfNotExists('pod_rs', 'created_at_index', 'created_at');
CALL AddIndexIfNotExists('pod', 'created_at_index', 'created_at');
CALL AddIndexIfNotExists('process', 'created_at_index', 'created_at');

DROP PROCEDURE IF EXISTS AddIndexIfNotExists;

UPDATE db_version SET version="6.6.1.73";
