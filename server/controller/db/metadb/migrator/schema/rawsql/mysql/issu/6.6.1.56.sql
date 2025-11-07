DROP PROCEDURE IF EXISTS RenameColumnIfExists;

CREATE PROCEDURE RenameColumnIfExists(
    IN tableName VARCHAR(255),
    IN oldColName VARCHAR(255),
    IN newColName VARCHAR(255),
    IN colType VARCHAR(255)
)
BEGIN
    DECLARE index_count INT;

    -- check if old column exists
    SELECT COUNT(*)
    INTO index_count
    FROM information_schema.columns
    WHERE table_schema = DATABASE()
    AND table_name = tableName
    AND column_name = newColName;

    -- if new column not exists, rename column
    IF index_count = 0 THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' CHANGE ', oldColName, ' ', newColName, ' ', colType);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

CALL RenameColumnIfExists('mail_server', 'user', 'user_name', 'TEXT NOT NULL');
CALL RenameColumnIfExists('plugin', 'user', 'user_name', "INTEGER NOT NULL DEFAULT 1 COMMENT '1: agent 2: server'");
CALL RenameColumnIfExists('genesis_process', 'user', 'user_name', "VARCHAR(256) DEFAULT ''");
CALL RenameColumnIfExists('data_source', "`interval`", 'interval_time', "INTEGER NOT NULL COMMENT 'uint: s'");
CALL RenameColumnIfExists('report_policy', '`interval`', 'interval_time', "enum('1d','1h') NOT NULL DEFAULT '1h'");

DROP PROCEDURE RenameColumnIfExists;

UPDATE db_version SET version='6.6.1.56';
