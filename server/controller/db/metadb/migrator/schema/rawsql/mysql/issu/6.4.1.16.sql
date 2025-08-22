DROP TABLE IF EXISTS `genesis_storage`;

CREATE TABLE IF NOT EXISTS genesis_storage (
    vtap_id     INTEGER NOT NULL PRIMARY KEY,
    node_ip     CHAR(48)
) ENGINE=MyISAM DEFAULT CHARSET = utf8mb4;
TRUNCATE TABLE genesis_storage;

UPDATE db_version SET version='6.4.1.16';