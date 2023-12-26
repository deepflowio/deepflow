DROP TABLE IF EXISTS `genesis_ippool`;

CREATE TABLE IF NOT EXISTS genesis_ippool (
    cluster_id CHAR(64) NOT NULL PRIMARY KEY,
    node_ip    CHAR(48),
    items      MEDIUMTEXT,
    last_seen  DATETIME
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4;
TRUNCATE TABLE genesis_ippool;

UPDATE db_version SET version='6.4.1.20';
