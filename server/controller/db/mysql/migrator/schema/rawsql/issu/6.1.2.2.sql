CREATE TABLE IF NOT EXISTS ch_k8s_labels (
    `pod_id`        INTEGER NOT NULL PRIMARY KEY,
    `labels`        TEXT,
    `l3_epc_id`     INTEGER,
    `pod_ns_id`     INTEGER,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

UPDATE db_version SET version = '6.1.2.2';
