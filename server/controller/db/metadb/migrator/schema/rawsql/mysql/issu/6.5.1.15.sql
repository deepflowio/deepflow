-- modify start, add upgrade sql
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

    -- 检查列是否存在
    SELECT COUNT(*)
    INTO col_count
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = tableName
    AND COLUMN_NAME = colName;

    -- 如果列不存在，则添加列
    IF col_count = 0 THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' ADD COLUMN ', colName, ' ', colType, ' DEFAULT ', defaultVal, ' AFTER ', afterCol);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;

    IF tableName = 'vl2_net' THEN
        UPDATE `vl2_net` a INNER JOIN `vl2` b ON a.vl2id = b.id SET a.domain = b.domain;
    END IF;

    IF tableName = 'routing_table' THEN
        UPDATE `routing_table` a INNER JOIN `vnet` b ON a.vnet_id = b.id SET a.domain = b.domain;
    END IF;

    IF tableName = 'security_group_rule' OR tableName = 'vm_security_group' THEN
        SET @sql = CONCAT('UPDATE ', tableName, ' a INNER JOIN security_group b ON a.sg_id = b.id SET a.domain = b.domain');
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;

    IF tableName = 'pod_service_port' OR tableName = 'pod_group_port' THEN
        SET @sql = CONCAT('UPDATE ', tableName, ' a INNER JOIN pod_service b ON a.pod_service_id = b.id SET a.domain = b.domain');
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;

    IF tableName = 'pod_ingress_rule' OR tableName = 'pod_ingress_rule_backend' THEN
        SET @sql = CONCAT('UPDATE ', tableName, ' a INNER JOIN pod_ingress b ON a.pod_ingress_id = b.id SET a.domain = b.domain');
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

CALL AddColumnAndSetIfNotExists('vl2_net', 'domain', 'CHAR(64)', '""', 'sub_domain');
CALL AddColumnAndSetIfNotExists('routing_table', 'domain', 'CHAR(64)', '""', 'nexthop');
CALL AddColumnAndSetIfNotExists('security_group_rule', 'domain', 'CHAR(64)', '""', 'action');
CALL AddColumnAndSetIfNotExists('vm_security_group', 'domain', 'CHAR(64)', '""', 'priority');
CALL AddColumnAndSetIfNotExists('pod_service_port', 'domain', 'CHAR(64)', '""', 'sub_domain');
CALL AddColumnAndSetIfNotExists('pod_group_port', 'domain', 'CHAR(64)', '""', 'sub_domain');
CALL AddColumnAndSetIfNotExists('pod_ingress_rule', 'domain', 'CHAR(64)', '""', 'sub_domain');
CALL AddColumnAndSetIfNotExists('pod_ingress_rule_backend', 'domain', 'CHAR(64)', '""', 'sub_domain');

CALL AddColumnAndSetIfNotExists('domain', 'team_id', 'INTEGER', '1', 'id');

DROP PROCEDURE AddColumnAndSetIfNotExists;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.5.1.15';
-- modify end
