DROP PROCEDURE IF EXISTS AddColumnAndSetIfNotExists;

CREATE PROCEDURE AddColumnAndSetIfNotExists(
    IN tableName VARCHAR(255),
    IN colName VARCHAR(255),
    IN colType VARCHAR(255),
    IN defaultVal VARCHAR(255),
    IN afterCol VARCHAR(255)
)
BEGIN
    DECLARE col_count INT;

    SELECT COUNT(*)
    INTO col_count
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = tableName
    AND COLUMN_NAME = colName;

    -- if the column does not exist, add the column
    IF col_count = 0 THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' ADD COLUMN ', colName, ' ', colType, ' DEFAULT ', defaultVal, ' AFTER ', afterCol);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

CALL AddColumnAndSetIfNotExists('routing_table', 'created_at', 'DATETIME NOT NULL', 'CURRENT_TIMESTAMP', 'lcuuid');
CALL AddColumnAndSetIfNotExists('routing_table', 'updated_at', 'DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP', 'CURRENT_TIMESTAMP', 'created_at');
CALL AddColumnAndSetIfNotExists('vl2_net', 'created_at', 'DATETIME NOT NULL', 'CURRENT_TIMESTAMP', 'lcuuid');
CALL AddColumnAndSetIfNotExists('vl2_net', 'updated_at', 'DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP', 'CURRENT_TIMESTAMP', 'created_at');
CALL AddColumnAndSetIfNotExists('vip', 'created_at', 'DATETIME NOT NULL', 'CURRENT_TIMESTAMP', 'vtap_id');
CALL AddColumnAndSetIfNotExists('vip', 'updated_at', 'DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP', 'CURRENT_TIMESTAMP', 'created_at');
CALL AddColumnAndSetIfNotExists('floatingip', 'created_at', 'DATETIME NOT NULL', 'CURRENT_TIMESTAMP', 'lcuuid');
CALL AddColumnAndSetIfNotExists('floatingip', 'updated_at', 'DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP', 'CURRENT_TIMESTAMP', 'created_at');
CALL AddColumnAndSetIfNotExists('nat_rule', 'created_at', 'DATETIME NOT NULL', 'CURRENT_TIMESTAMP', 'lcuuid');
CALL AddColumnAndSetIfNotExists('nat_rule', 'updated_at', 'DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP', 'CURRENT_TIMESTAMP', 'created_at');
CALL AddColumnAndSetIfNotExists('nat_vm_connection', 'created_at', 'DATETIME NOT NULL', 'CURRENT_TIMESTAMP', 'lcuuid');
CALL AddColumnAndSetIfNotExists('nat_vm_connection', 'updated_at', 'DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP', 'CURRENT_TIMESTAMP', 'created_at');
CALL AddColumnAndSetIfNotExists('lb_target_server', 'created_at', 'DATETIME NOT NULL', 'CURRENT_TIMESTAMP', 'lcuuid');
CALL AddColumnAndSetIfNotExists('lb_target_server', 'updated_at', 'DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP', 'CURRENT_TIMESTAMP', 'created_at');
CALL AddColumnAndSetIfNotExists('lb_vm_connection', 'created_at', 'DATETIME NOT NULL', 'CURRENT_TIMESTAMP', 'lcuuid');
CALL AddColumnAndSetIfNotExists('lb_vm_connection', 'updated_at', 'DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP', 'CURRENT_TIMESTAMP', 'created_at');
CALL AddColumnAndSetIfNotExists('vm_pod_node_connection', 'created_at', 'DATETIME NOT NULL', 'CURRENT_TIMESTAMP', 'lcuuid');
CALL AddColumnAndSetIfNotExists('vm_pod_node_connection', 'updated_at', 'DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP', 'CURRENT_TIMESTAMP', 'created_at');
CALL AddColumnAndSetIfNotExists('pod_service_port', 'created_at', 'DATETIME NOT NULL', 'CURRENT_TIMESTAMP', 'lcuuid');
CALL AddColumnAndSetIfNotExists('pod_service_port', 'updated_at', 'DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP', 'CURRENT_TIMESTAMP', 'created_at');
CALL AddColumnAndSetIfNotExists('pod_group_port', 'created_at', 'DATETIME NOT NULL', 'CURRENT_TIMESTAMP', 'lcuuid');
CALL AddColumnAndSetIfNotExists('pod_group_port', 'updated_at', 'DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP', 'CURRENT_TIMESTAMP', 'created_at');
CALL AddColumnAndSetIfNotExists('pod_ingress_rule', 'created_at', 'DATETIME NOT NULL', 'CURRENT_TIMESTAMP', 'lcuuid');
CALL AddColumnAndSetIfNotExists('pod_ingress_rule', 'updated_at', 'DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP', 'CURRENT_TIMESTAMP', 'created_at');
CALL AddColumnAndSetIfNotExists('pod_ingress_rule_backend', 'created_at', 'DATETIME NOT NULL', 'CURRENT_TIMESTAMP', 'lcuuid');
CALL AddColumnAndSetIfNotExists('pod_ingress_rule_backend', 'updated_at', 'DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP', 'CURRENT_TIMESTAMP', 'created_at');

DROP PROCEDURE AddColumnAndSetIfNotExists;

-- whether default db or not, update db_version to latest, remember update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.5.1.41';
-- modify end
