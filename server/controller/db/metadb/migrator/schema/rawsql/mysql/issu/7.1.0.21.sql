CREATE TABLE IF NOT EXISTS genesis_cluster (
    id          CHAR(64) NOT NULL PRIMARY KEY,
    node_ip     CHAR(48)
) ENGINE=innodb DEFAULT CHARSET = utf8mb4;
TRUNCATE TABLE genesis_cluster;

UPDATE db_version SET version='7.1.0.21';
