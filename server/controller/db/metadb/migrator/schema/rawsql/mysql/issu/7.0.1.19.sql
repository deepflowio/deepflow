DROP PROCEDURE IF EXISTS AddColumnIfNotExists;

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

CALL AddColumnIfNotExists('peer_connection', 'team_id', 'INTEGER NOT NULL', 'label');

DROP PROCEDURE AddColumnIfNotExists;

UPDATE peer_connection JOIN domain ON peer_connection.domain = domain.lcuuid SET peer_connection.team_id = domain.team_id;

DROP PROCEDURE IF EXISTS ModifyColumnIfExists;
CREATE PROCEDURE ModifyColumnIfExists(
    IN tableName VARCHAR(255),
    IN colName VARCHAR(255),
    IN colType VARCHAR(255)
)
BEGIN
    DECLARE column_count INT;

    SELECT COUNT(*)
    INTO column_count
    FROM information_schema.columns
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = tableName
    AND column_name = colName;

    IF column_count > 0 THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' MODIFY COLUMN ', colName, ' ', colType);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

CALL ModifyColumnIfExists('peer_connection', 'local_epc_id', 'INTEGER DEFAULT NULL');
CALL ModifyColumnIfExists('peer_connection', 'remote_epc_id', 'INTEGER DEFAULT NULL');
DROP PROCEDURE ModifyColumnIfExists;

UPDATE db_version SET version='7.0.1.19';
