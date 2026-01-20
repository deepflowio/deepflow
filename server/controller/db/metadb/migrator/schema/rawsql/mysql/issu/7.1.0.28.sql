
UPDATE domain SET cluster_id = CONCAT('d-', UUID_SHORT()) WHERE cluster_id IS NULL OR cluster_id = '';

ALTER TABLE custom_service MODIFY COLUMN type INTEGER DEFAULT 0 COMMENT '0: unknown 1: IP 2: PORT 3: chost 4: pod_service 5: pod_group 6:pod 7: host';

-- Update DB version
UPDATE db_version SET version='7.1.0.28';
