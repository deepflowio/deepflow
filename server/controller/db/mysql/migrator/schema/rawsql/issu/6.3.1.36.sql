CREATE TABLE IF NOT EXISTS go_genesis_vip (
    id          INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    lcuuid      CHAR(64),
    ip          CHAR(64),
    vtap_id     INTEGER,
    node_ip     CHAR(48)
) ENGINE=innodb DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1;
TRUNCATE TABLE go_genesis_vip;

UPDATE db_version SET version='6.3.1.36';

