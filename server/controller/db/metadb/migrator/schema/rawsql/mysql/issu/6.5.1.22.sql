DROP TABLE IF EXISTS ch_chost;
DROP TABLE IF EXISTS ch_device;
DROP TABLE IF EXISTS ch_pod_service;
DROP TABLE IF EXISTS ch_az;
DROP TABLE IF EXISTS ch_pod_node;
DROP TABLE IF EXISTS ch_pod_ns;
DROP TABLE IF EXISTS ch_pod_group;
DROP TABLE IF EXISTS ch_pod;
DROP TABLE IF EXISTS ch_pod_cluster;
DROP TABLE IF EXISTS ch_subnet;
DROP TABLE IF EXISTS ch_gprocess;
DROP TABLE IF EXISTS ch_l3_epc;
DROP TABLE IF EXISTS ch_pod_ingress;
DROP TABLE IF EXISTS ch_pod_service_k8s_annotation;
DROP TABLE IF EXISTS ch_pod_service_k8s_annotations;
DROP TABLE IF EXISTS ch_pod_service_k8s_label;
DROP TABLE IF EXISTS ch_pod_service_k8s_labels;
DROP TABLE IF EXISTS ch_pod_k8s_label;
DROP TABLE IF EXISTS ch_pod_k8s_labels;
DROP TABLE IF EXISTS ch_pod_k8s_annotation;
DROP TABLE IF EXISTS ch_pod_k8s_annotations;
DROP TABLE IF EXISTS ch_pod_k8s_env;
DROP TABLE IF EXISTS ch_pod_k8s_envs;
DROP TABLE IF EXISTS ch_chost_cloud_tag;
DROP TABLE IF EXISTS ch_chost_cloud_tags;
DROP TABLE IF EXISTS ch_pod_ns_cloud_tag;
DROP TABLE IF EXISTS ch_pod_ns_cloud_tags;
DROP TABLE IF EXISTS ch_os_app_tag;
DROP TABLE IF EXISTS ch_os_app_tags;
DELETE FROM ch_vtap;
DELETE FROM ch_vtap_port;


CREATE TABLE IF NOT EXISTS ch_chost (
    `id`              INTEGER NOT NULL PRIMARY KEY,
    `name`            VARCHAR(256),
    `host_id`         INTEGER,
    `l3_epc_id`       INTEGER,
    `ip`              CHAR(64),
    `hostname`        VARCHAR(256),
    `team_id`         INTEGER,
    `domain_id`       INTEGER,
    `updated_at`      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_device (
    devicetype              INTEGER NOT NULL,
    deviceid                INTEGER NOT NULL,
    name                    TEXT,
    uid                     CHAR(64),
    icon_id                 INTEGER,
    ip                      CHAR(64),
    hostname                VARCHAR(256),
    team_id                 INTEGER,
    domain_id               INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (devicetype, deviceid)
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_pod_service (
    `id`              INTEGER NOT NULL PRIMARY KEY,
    `name`            VARCHAR(256),
    `pod_cluster_id`  INTEGER,
    `pod_ns_id`       INTEGER,
    `team_id`         INTEGER,
    `domain_id`       INTEGER,
    `updated_at`      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_az (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    icon_id                 INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_pod_node (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    icon_id                 INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_pod_ns (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    icon_id                 INTEGER,
    pod_cluster_id          INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_pod_group (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    pod_group_type          INTEGER DEFAULT NULL,
    icon_id                 INTEGER,
    pod_cluster_id          INTEGER,
    pod_ns_id               INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_pod (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    icon_id                 INTEGER,
    pod_cluster_id          INTEGER,
    pod_ns_id               INTEGER,
    pod_node_id             INTEGER,
    pod_service_id          INTEGER,
    pod_group_id            INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_pod_cluster (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    icon_id                 INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_subnet (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    icon_id                 INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_gprocess (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    TEXT,
    icon_id                 INTEGER,
    chost_id                INTEGER,
    l3_epc_id               INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_l3_epc (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    uid                     CHAR(64),
    icon_id                 INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_pod_ingress (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    team_id                 INTEGER,
    domain_id               INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_pod_service_k8s_annotation (
    `id`            INTEGER NOT NULL,
    `key`           VARCHAR(256) NOT NULL,
    `value`         VARCHAR(256),
    `l3_epc_id`     INTEGER,
    `pod_ns_id`     INTEGER,
    `team_id`       INTEGER,
    `domain_id`     INTEGER,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`, `key`)
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_pod_service_k8s_annotations (
    `id`            INTEGER NOT NULL PRIMARY KEY,
    `annotations`   TEXT,
    `l3_epc_id`     INTEGER,
    `pod_ns_id`     INTEGER,
    `team_id`       INTEGER,
    `domain_id`     INTEGER,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_pod_service_k8s_label (
    `id`            INTEGER NOT NULL,
    `key`           VARCHAR(256) NOT NULL,
    `value`         VARCHAR(256),
    `l3_epc_id`     INTEGER,
    `pod_ns_id`     INTEGER,
    `team_id`       INTEGER,
    `domain_id`     INTEGER,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`, `key`)
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_pod_service_k8s_labels (
    `id`            INTEGER NOT NULL PRIMARY KEY,
    `labels`        TEXT,
    `l3_epc_id`     INTEGER,
    `pod_ns_id`     INTEGER,
    `team_id`       INTEGER,
    `domain_id`     INTEGER,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_pod_k8s_label (
    `id`            INTEGER NOT NULL,
    `key`           VARCHAR(256) NOT NULL,
    `value`         VARCHAR(256),
    `l3_epc_id`     INTEGER,
    `pod_ns_id`     INTEGER,
    `team_id`       INTEGER,
    `domain_id`     INTEGER,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`, `key`)
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_pod_k8s_labels (
    `id`            INTEGER NOT NULL PRIMARY KEY,
    `labels`        TEXT,
    `l3_epc_id`     INTEGER,
    `pod_ns_id`     INTEGER,
    `team_id`       INTEGER,
    `domain_id`     INTEGER,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_pod_k8s_annotation (
    `id`            INTEGER NOT NULL,
    `key`           VARCHAR(256) NOT NULL,
    `value`         VARCHAR(256),
    `l3_epc_id`     INTEGER,
    `pod_ns_id`     INTEGER,
    `team_id`       INTEGER,
    `domain_id`     INTEGER,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`, `key`)
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_pod_k8s_annotations (
    `id`            INTEGER NOT NULL PRIMARY KEY,
    `annotations`   TEXT,
    `l3_epc_id`     INTEGER,
    `pod_ns_id`     INTEGER,
    `team_id`       INTEGER,
    `domain_id`     INTEGER,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_pod_k8s_env (
    `id`            INTEGER NOT NULL,
    `key`           VARCHAR(256) NOT NULL,
    `value`         VARCHAR(256),
    `l3_epc_id`     INTEGER,
    `pod_ns_id`     INTEGER,
    `team_id`       INTEGER,
    `domain_id`     INTEGER,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`, `key`)
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_pod_k8s_envs (
    `id`            INTEGER NOT NULL PRIMARY KEY,
    `envs`          TEXT,
    `l3_epc_id`     INTEGER,
    `pod_ns_id`     INTEGER,
    `team_id`       INTEGER,
    `domain_id`     INTEGER,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_chost_cloud_tag (
    `id`            INTEGER NOT NULL,
    `key`           VARCHAR(256) NOT NULL,
    `value`         VARCHAR(256),
    `team_id`       INTEGER,
    `domain_id`     INTEGER,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`, `key`)
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_chost_cloud_tags (
    `id`            INTEGER NOT NULL PRIMARY KEY,
    `cloud_tags`    TEXT,
    `team_id`       INTEGER,
    `domain_id`     INTEGER,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_pod_ns_cloud_tag (
    `id`            INTEGER NOT NULL,
    `key`           VARCHAR(256) NOT NULL,
    `value`         VARCHAR(256),
    `team_id`       INTEGER,
    `domain_id`     INTEGER,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`, `key`)
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_pod_ns_cloud_tags (
    `id`            INTEGER NOT NULL PRIMARY KEY,
    `cloud_tags`    TEXT,
    `team_id`       INTEGER,
    `domain_id`     INTEGER,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_os_app_tag (
    `pid`           INTEGER NOT NULL,
    `key`           VARCHAR(256) NOT NULL,
    `value`         VARCHAR(256),
    `team_id`       INTEGER,
    `domain_id`     INTEGER,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`pid`, `key`)
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_os_app_tags (
    `pid`           INTEGER NOT NULL PRIMARY KEY,
    `os_app_tags`   TEXT,
    `team_id`       INTEGER,
    `domain_id`     INTEGER,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.5.1.22';
-- modify end

