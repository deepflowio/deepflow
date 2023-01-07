CREATE TABLE IF NOT EXISTS process (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    vtap_id             INTEGER NOT NULL DEFAULT 0,
    pid                 INTEGER NOT NULL DEFAULT 0,
    process_name        VARCHAR(256) DEFAULT '',
    command_line        TEXT,
    user_name           VARCHAR(256) DEFAULT '',
    start_time          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    os_app_tags         TEXT COMMENT 'separated by ,',
    sub_domain          CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;

UPDATE db_version SET version = '6.2.1.1';
