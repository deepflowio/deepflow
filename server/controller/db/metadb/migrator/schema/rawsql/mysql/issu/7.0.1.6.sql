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

CALL AddColumnIfNotExists('vinterface', 'epc_id', "INTEGER DEFAULT 0", 'vtap_id');

DROP PROCEDURE AddColumnIfNotExists;

DROP PROCEDURE UpdateVInterfaceEpcID;
DELIMITER //
CREATE PROCEDURE UpdateVInterfaceEpcID(
    IN deviceTable VARCHAR(255),  -- vm 表名
    IN deviceType INT             -- vinterface.devicetype
)
BEGIN
    -- 动态生成并执行 UPDATE 语句
    SET @update_sql = CONCAT(
        'UPDATE vinterface ',
        'JOIN ', deviceTable, ' ON vinterface.deviceid = ', deviceTable, '.id ',
        'SET vinterface.epc_id = ', deviceTable, '.epc_id ',
        'WHERE vinterface.devicetype = ', deviceType
    );

    -- 准备并执行动态 SQL
    PREPARE stmt FROM @update_sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
END //

DELIMITER ;

-- 调用存储过程
CALL UpdateVInterfaceEpcID('vm', 1);
CALL UpdateVInterfaceEpcID('vnet', 5);
CALL UpdateVInterfaceEpcID('dhcp_port', 9);
CALL UpdateVInterfaceEpcID('pod', 10);
CALL UpdateVInterfaceEpcID('pod_service', 11);
CALL UpdateVInterfaceEpcID('redis_instance', 12);
CALL UpdateVInterfaceEpcID('rds_instance', 13);
CALL UpdateVInterfaceEpcID('pod_node', 14);
CALL UpdateVInterfaceEpcID('lb', 15);
CALL UpdateVInterfaceEpcID('nat_gateway', 16);

DROP PROCEDURE UpdateVInterfaceEpcID;

-- 宿主机类型的 vinterface 更新 epc_id，使用子网 vl2 表的 epc_id
UPDATE vinterface
JOIN vl2 ON vinterface.subnetid = vl2.id
SET vinterface.epc_id = vl2.epc_id
WHERE vinterface.devicetype = 6;

UPDATE db_version SET version='7.0.1.6';
