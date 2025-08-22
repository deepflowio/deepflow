ALTER TABLE `ch_pod_ns` 
    ADD COLUMN `pod_cluster_id` INTEGER;

ALTER TABLE `ch_pod_group` 
    ADD COLUMN `pod_cluster_id` INTEGER,
    ADD COLUMN `pod_ns_id` INTEGER;

ALTER TABLE `ch_pod` 
    ADD COLUMN `pod_cluster_id` INTEGER,
    ADD COLUMN `pod_ns_id` INTEGER,
    ADD COLUMN `pod_node_id` INTEGER,
    ADD COLUMN `pod_service_id` INTEGER,
    ADD COLUMN `pod_group_id` INTEGER;


CREATE TABLE IF NOT EXISTS ch_pod_service (
    `id`              INTEGER NOT NULL PRIMARY KEY,
    `name`            VARCHAR(256),
    `pod_cluster_id`  INTEGER,
    `pod_ns_id`       INTEGER,
    `updated_at`      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_chost (
    `id`              INTEGER NOT NULL PRIMARY KEY,
    `name`            VARCHAR(256),
    `host_id`         INTEGER,
    `vpc_id`          INTEGER,
    `updated_at`      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/version.go
UPDATE db_version SET version='6.4.1.5';
-- modify end
