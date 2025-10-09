CREATE TABLE IF NOT EXISTS go_genesis_storage (
    id          INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    vtap_id     INTEGER,
    node_ip     CHAR(48)
) ENGINE = innodb DEFAULT CHARSET = utf8mb4 AUTO_INCREMENT = 1;

UPDATE db_version SET version = '6.1.1.20';
