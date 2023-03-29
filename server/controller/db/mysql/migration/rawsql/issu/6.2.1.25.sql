START TRANSACTION;

-- modify start, add upgrade sql

RENAME TABLE ch_k8s_label TO ch_pod_k8s_label;
RENAME TABLE ch_k8s_labels TO ch_pod_k8s_labels;

CREATE TABLE IF NOT EXISTS ch_pod_service_k8s_label (
    `pod_id`        INTEGER NOT NULL,
    `key`           VARCHAR(256) NOT NULL,
    `value`         VARCHAR(256),
    `l3_epc_id`     INTEGER,
    `pod_ns_id`     INTEGER,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`pod_id`, `key`)
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_pod_service_k8s_labels (
    `pod_id`        INTEGER NOT NULL PRIMARY KEY,
    `labels`        TEXT,
    `l3_epc_id`     INTEGER,
    `pod_ns_id`     INTEGER,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;
-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.2.1.25';
-- modify end

COMMIT;