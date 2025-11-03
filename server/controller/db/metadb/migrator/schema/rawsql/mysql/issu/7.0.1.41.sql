DROP PROCEDURE IF EXISTS ModifyColumnTypeIfExists;

-- Procedure to modify column if it exists
CREATE PROCEDURE ModifyColumnTypeIfExists(
    IN tableName VARCHAR(255),
    IN colName VARCHAR(255),
    IN colType VARCHAR(255)
)
BEGIN
    SET @sql = CONCAT('ALTER TABLE ', tableName, ' MODIFY COLUMN ', colName, ' ', colType);
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
END;

-- Modify name len=255 for npb_policy table
CALL ModifyColumnTypeIfExists('npb_policy', 'name', 'CHAR(255)');

-- Modify name len=255 for acl table
CALL ModifyColumnTypeIfExists('acl', 'name', 'CHAR(255)');

DROP PROCEDURE ModifyColumnTypeIfExists;

UPDATE db_version SET version='7.0.1.41';
