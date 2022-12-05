CREATE TABLE IF NOT EXISTS domain_additional_resource (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    domain              CHAR(64) DEFAULT '',
    content             TEXT,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
 ) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;

UPDATE db_version SET version = '6.1.8.7';
