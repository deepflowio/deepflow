CREATE TABLE IF NOT EXISTS vip (
    id          INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    lcuuid      CHAR(64),
    ip          CHAR(64),
    domain      CHAR(64) DEFAULT '',
    vtap_id     INTEGER
) ENGINE=innodb DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1;
TRUNCATE TABLE vip;

UPDATE db_version SET version='6.3.1.37';

