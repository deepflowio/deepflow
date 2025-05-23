
CREATE TABLE IF NOT EXISTS config_map (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(256) NOT NULL,
    data                TEXT COMMENT 'yaml',
    data_hash           CHAR(64) DEFAULT '',
    pod_namespace_id    INTEGER NOT NULL,
    pod_cluster_id      INTEGER NOT NULL,
    epc_id              INTEGER NOT NULL,
    az                  CHAR(64) DEFAULT '',
    region              CHAR(64) DEFAULT '',
    sub_domain          CHAR(64) DEFAULT '',
    domain              CHAR(64) NOT NULL,
    lcuuid              CHAR(64) NOT NULL,
    synced_at           DATETIME DEFAULT NULL,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL,
    INDEX data_hash_index(data_hash),
    INDEX domain_index(domain)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;

CREATE TABLE IF NOT EXISTS pod_group_config_map_connection (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    pod_group_id        INTEGER NOT NULL,
    config_map_id       INTEGER NOT NULL,
    sub_domain          CHAR(64) DEFAULT '',
    domain              CHAR(64) NOT NULL,
    lcuuid              CHAR(64) NOT NULL,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX pod_group_id_index(pod_group_id),
    INDEX config_map_id_index(config_map_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;

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

CALL AddColumnIfNotExists('pod_service', 'metadata', 'TEXT COMMENT "yaml"', 'service_cluster_ip');
CALL AddColumnIfNotExists('pod_service', 'metadata_hash', 'CHAR(64) DEFAULT ""', 'metadata');
CALL AddColumnIfNotExists('pod_service', 'spec', 'TEXT COMMENT "yaml"', 'metadata_hash');
CALL AddColumnIfNotExists('pod_service', 'spec_hash', 'CHAR(64) DEFAULT ""', 'spec');
CALL AddColumnIfNotExists('pod_group', 'metadata', 'TEXT COMMENT "yaml"', 'label');
CALL AddColumnIfNotExists('pod_group', 'metadata_hash', 'CHAR(64) DEFAULT ""', 'metadata');
CALL AddColumnIfNotExists('pod_group', 'spec', 'TEXT COMMENT "yaml"', 'metadata_hash');
CALL AddColumnIfNotExists('pod_group', 'spec_hash', 'CHAR(64) DEFAULT ""', 'spec');

DROP PROCEDURE AddColumnIfNotExists;

UPDATE db_version SET version='7.0.1.20';
