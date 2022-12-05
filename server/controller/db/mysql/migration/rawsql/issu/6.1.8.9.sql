
CREATE TABLE IF NOT EXISTS resource_event (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    domain              CHAR(64) DEFAULT '',
    sub_domain          CHAR(64) DEFAULT '',
    resource_lcuuid     CHAR(64) DEFAULT '',
    content             TEXT,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;

UPDATE db_version SET version = '6.1.8.9';
