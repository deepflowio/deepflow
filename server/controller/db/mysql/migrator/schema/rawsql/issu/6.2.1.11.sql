USE deepflow;

CREATE TABLE IF NOT EXISTS ch_os_app_tags (
    `pid`           INTEGER NOT NULL PRIMARY KEY,
    `os_app_tags`   TEXT,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

UPDATE db_version SET version = '6.2.1.11';