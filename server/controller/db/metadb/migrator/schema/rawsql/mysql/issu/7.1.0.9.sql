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

CALL AddColumnIfNotExists('pod_cluster', 'uid', "CHAR(64) DEFAULT ''", 'domain');
CALL AddColumnIfNotExists('pod_namespace', 'uid', "CHAR(64) DEFAULT ''", 'domain');
CALL AddColumnIfNotExists('pod_service', 'uid', "CHAR(64) DEFAULT ''", 'domain');
CALL AddColumnIfNotExists('pod_group', 'uid', "CHAR(64) DEFAULT ''", 'domain');
CALL AddColumnIfNotExists('custom_service', 'match_type', "INTEGER DEFAULT 0 COMMENT '0: unkonwn 1: name match 2: uid match'", 'type');
CALL AddColumnIfNotExists('custom_service', 'pod_namespace_id', "INTEGER DEFAULT 0", 'match_type');
CALL AddColumnIfNotExists('custom_service', 'pod_cluster_id', "INTEGER DEFAULT 0", 'match_type');

DROP PROCEDURE AddColumnIfNotExists;

ALTER TABLE custom_service MODIFY COLUMN type INTEGER DEFAULT 0 COMMENT '0: unknown 1: IP 2: PORT 3: chost 4: pod_service 5: pod_group';
ALTER TABLE custom_service MODIFY COLUMN match_type INTEGER DEFAULT 1 COMMENT '0: unkonwn 1: name match 2: uid match';

UPDATE pod_cluster SET uid = CONCAT('pod_cluster-', UUID_SHORT()) WHERE uid IS NULL OR uid = '';
UPDATE pod_namespace SET uid = CONCAT('pod_ns-', UUID_SHORT()) WHERE uid IS NULL OR uid = '';
UPDATE pod_service SET uid = CONCAT('pod_service-', UUID_SHORT()) WHERE uid IS NULL OR uid = '';
UPDATE pod_group SET uid = CONCAT('pod_group-', UUID_SHORT()) WHERE uid IS NULL OR uid = '';
UPDATE vm SET uid = CONCAT('chost-', UUID_SHORT()) WHERE uid IS NULL OR uid = '';
UPDATE epc SET uid = CONCAT('vpc-', UUID_SHORT()) WHERE uid IS NULL OR uid = '';

UPDATE db_version SET version='7.1.0.9';
