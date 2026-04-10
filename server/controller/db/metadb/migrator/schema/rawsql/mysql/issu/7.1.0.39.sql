DROP PROCEDURE IF EXISTS AddIndexIfNotExists;

CREATE PROCEDURE AddIndexIfNotExists(
    IN tableName VARCHAR(255),
    IN indexName VARCHAR(255),
    IN indexCol  VARCHAR(255)
)
BEGIN
    DECLARE index_count INT;

    SELECT COUNT(*)
    INTO index_count
    FROM information_schema.statistics
    WHERE table_schema = DATABASE()
      AND table_name   = tableName
      AND column_name  = indexCol;

    IF index_count = 0 THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' ADD INDEX ', indexName, ' (', indexCol, ') USING BTREE');
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

DROP PROCEDURE IF EXISTS AddNamedIndexIfNotExists;

-- AddNamedIndexIfNotExists checks by index name (required for composite indexes where
-- the leading column may already have a separate single-column index).
CREATE PROCEDURE AddNamedIndexIfNotExists(
    IN tableName VARCHAR(255),
    IN indexName VARCHAR(255),
    IN indexDef  VARCHAR(1024)
)
BEGIN
    DECLARE index_count INT;

    SELECT COUNT(*)
    INTO index_count
    FROM information_schema.statistics
    WHERE table_schema = DATABASE()
      AND table_name   = tableName
      AND index_name   = indexName;

    IF index_count = 0 THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' ADD INDEX ', indexName, ' ', indexDef);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

DROP PROCEDURE IF EXISTS DeleteIndexIfExists;

CREATE PROCEDURE DeleteIndexIfExists(
    IN tableName VARCHAR(255),
    IN indexName VARCHAR(255)
)
BEGIN
    DECLARE index_count INT;

    SELECT COUNT(*)
    INTO index_count
    FROM information_schema.statistics
    WHERE table_schema = DATABASE()
      AND table_name   = tableName
      AND index_name   = indexName;

    IF index_count > 0 THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' DROP INDEX ', indexName);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

-- P0: Remove redundant index on vm(id) — id is already the PRIMARY KEY in InnoDB
CALL DeleteIndexIfExists('vm', 'id_index');

-- P0: vinterface — 10w-50w rows; devicetype_index speeds up pod/vm data-build subqueries
--     (WHERE devicetype = N); lcuuid_index speeds up recorder per-resource Update/Delete
CALL AddIndexIfNotExists('vinterface', 'devicetype_index', 'devicetype');
CALL AddIndexIfNotExists('vinterface', 'lcuuid_index', 'lcuuid');

-- P0: vinterface_ip — 10w-50w rows; recorder per-resource Update/Delete by lcuuid
CALL AddIndexIfNotExists('vinterface_ip', 'lcuuid_index', 'lcuuid');

-- P0: ip_resource — 5w-50w rows; recorder per-resource Update/Delete by lcuuid
CALL AddIndexIfNotExists('ip_resource', 'lcuuid_index', 'lcuuid');

-- P1: vtap — multi-module (monitor/genesis/trisolaris) high-frequency lcuuid operations
CALL AddIndexIfNotExists('vtap', 'lcuuid_index', 'lcuuid');

-- P1: pod_rs — recorder CRUD by lcuuid
CALL AddIndexIfNotExists('pod_rs', 'lcuuid_index', 'lcuuid');

-- P1: pod_service_port — 1w-1.5w rows; recorder CRUD by lcuuid
CALL AddIndexIfNotExists('pod_service_port', 'lcuuid_index', 'lcuuid');

-- P1: vl2_net(subnet) — cleaner cascade delete and subnet queries by vl2id
CALL AddIndexIfNotExists('vl2_net', 'vl2id_index', 'vl2id');

-- P1: vm_pod_node_connection — cleaner cascade delete by pod_node_id
CALL AddIndexIfNotExists('vm_pod_node_connection', 'pod_node_id_index', 'pod_node_id');

-- P1: pod — composite indexes for HTTP API paginated + ORDER BY created_at queries
--     pod_namespace_id and pod_cluster_id already have single-column indexes; these
--     composites add ORDER BY support without filesort (use AddNamedIndexIfNotExists
--     since the leading column already has a separate index)
CALL AddNamedIndexIfNotExists('pod', 'pod_ns_created_at_index',      '(pod_namespace_id, created_at)');
CALL AddNamedIndexIfNotExists('pod', 'pod_cluster_created_at_index', '(pod_cluster_id,   created_at)');

-- P1: process — large table (10w-50w rows); vtap_id_index enables DB-side filtering
--     once the application layer is refactored to push vtap_id filters to SQL
CALL AddIndexIfNotExists('process', 'vtap_id_index', 'vtap_id');

-- P2: domain / sub_domain — team_id_index for FPermit non-admin per-request WHERE team_id IN (?)
CALL AddIndexIfNotExists('domain',     'team_id_index', 'team_id');
CALL AddIndexIfNotExists('sub_domain', 'team_id_index', 'team_id');

-- P2: pod / pod_group — deleted_at_index for cleaner WHERE deleted_at < ? (soft-delete cleanup)
CALL AddIndexIfNotExists('pod',       'deleted_at_index', 'deleted_at');
CALL AddIndexIfNotExists('pod_group', 'deleted_at_index', 'deleted_at');

-- P2: ch_os_app_tag — 10w+ rows (PK=(id,key)); composite index matches tagrecorder healer
--     WHERE domain_id = ? AND sub_domain_id = ? and ClickHouse dict ORDER BY updated_at
CALL AddNamedIndexIfNotExists('ch_os_app_tag', 'domain_sub_domain_id_updated_at_index',
    '(domain_id, sub_domain_id, id, updated_at ASC)');

DROP PROCEDURE IF EXISTS AddIndexIfNotExists;
DROP PROCEDURE IF EXISTS AddNamedIndexIfNotExists;
DROP PROCEDURE IF EXISTS DeleteIndexIfExists;

UPDATE db_version SET version='7.1.0.39';
