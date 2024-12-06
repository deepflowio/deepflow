-- for /db/mysql/migration/script/upgrade_vtap_group_config.go
DROP PROCEDURE IF EXISTS RenameColumnIfExists;

CREATE PROCEDURE RenameColumnIfExists(
    IN tableName VARCHAR(255),
    IN newColName VARCHAR(255),
    IN oldColName VARCHAR(255)
)
BEGIN
    DECLARE index_count INT;

    -- check if old column exists
    SELECT COUNT(*)
    INTO index_count
    FROM information_schema.columns
    WHERE table_schema = DATABASE()
    AND table_name = tableName
    AND column_name = oldColName;

    -- if old column exists, rename column
    IF index_count = 0 THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' CHANGE ', oldColName, ' ', newColName, '()');
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

CALL RenameColumnIfExists('mail_server', 'user', 'user_name');
CALL RenameColumnIfExists('plugin', 'user', 'user_name');
CALL RenameColumnIfExists('genesis_process', 'user', 'user_name');
CALL RenameColumnIfExists('data_source', '`interval`', '`interval_time`');
CALL RenameColumnIfExists('report_policy', '`interval`', '`interval_time`');

DROP PROCEDURE RenameColumnIfExists;


UPDATE db_version SET version='6.6.1.18';