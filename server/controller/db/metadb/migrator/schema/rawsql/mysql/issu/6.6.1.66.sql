-- ColumnExists procedure
DROP PROCEDURE IF EXISTS ColumnExists;

CREATE PROCEDURE ColumnExists(
    IN  p_table_name VARCHAR(255),
    IN  p_col_name   VARCHAR(255),
    OUT p_exists     TINYINT(1)
)
BEGIN
    SELECT COUNT(*) > 0
    INTO p_exists
    FROM information_schema.columns
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = p_table_name
      AND COLUMN_NAME  = p_col_name;
END;

-- AddColumnIfNotExists procedure
DROP PROCEDURE IF EXISTS AddColumnIfNotExists;

CREATE PROCEDURE AddColumnIfNotExists(
    IN tableName VARCHAR(255),
    IN colName VARCHAR(255),
    IN colType VARCHAR(255),
    IN afterCol VARCHAR(255)
)
BEGIN
    CALL ColumnExists(tableName, colName, @exists);
    IF NOT @exists THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' ADD COLUMN ', colName, ' ', colType, ' AFTER ', afterCol);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

-- UpdateColumnIfExists procedure
DROP PROCEDURE IF EXISTS UpdateColumnIfExists;

CREATE PROCEDURE UpdateColumnIfExists(
    IN tableName VARCHAR(255),
    IN colName VARCHAR(255),
    IN defaultValue VARCHAR(255)
)
BEGIN
    CALL ColumnExists(tableName, colName, @exists);
    IF @exists THEN
        SET @sql = CONCAT('UPDATE ', tableName, ' SET ', colName, ' = ', defaultValue, ' WHERE ', colName, ' IS NULL');
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

-- add trigger configuration fields
CALL AddColumnIfNotExists('alarm_policy', 'trigger_mode', 'INTEGER DEFAULT 1 COMMENT ''1-连续次数 2-时间窗口''', 'trigger_recovery_event');
CALL AddColumnIfNotExists('alarm_policy', 'trigger_count', 'INTEGER DEFAULT 1 COMMENT ''触发次数''', 'trigger_mode');
CALL AddColumnIfNotExists('alarm_policy', 'trigger_window_minutes', 'INTEGER DEFAULT 0 COMMENT ''时间窗口(分钟)''', 'trigger_count');

CALL UpdateColumnIfExists('alarm_policy', 'trigger_mode', '1');
CALL UpdateColumnIfExists('alarm_policy', 'trigger_count', '1');
CALL UpdateColumnIfExists('alarm_policy', 'trigger_window_minutes', '0');

-- add alarm_event_state for ongoing events
CREATE TABLE IF NOT EXISTS alarm_event_state (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    event_id                CHAR(64) NOT NULL COMMENT '聚合事件ID',
    state                   INTEGER COMMENT '0-ongoing 1-ended',
    event_payload           TEXT COMMENT '事件JSON',
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_event_id(event_id)
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;

-- Cleanup procedures
DROP PROCEDURE IF EXISTS ColumnExists;
DROP PROCEDURE IF EXISTS AddColumnIfNotExists;
DROP PROCEDURE IF EXISTS UpdateColumnIfExists;

-- Update DB version
UPDATE db_version SET version='6.6.1.66';
