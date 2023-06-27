
-- modify start, add upgrade sql
CREATE TABLE IF NOT EXISTS ch_pod_k8s_env (
    `id`            INTEGER NOT NULL,
    `key`           VARCHAR(256) NOT NULL,
    `value`         VARCHAR(256),
    `l3_epc_id`     INTEGER,
    `pod_ns_id`     INTEGER,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`, `key`)
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_pod_k8s_envs (
    `id`            INTEGER NOT NULL PRIMARY KEY,
    `envs`          TEXT,
    `l3_epc_id`     INTEGER,
    `pod_ns_id`     INTEGER,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/version.go
UPDATE db_version SET version='6.3.1.9';
-- modify end
