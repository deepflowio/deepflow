USE deepflow;

CREATE TABLE IF NOT EXISTS ch_os_app_tag (
    `pid`           INTEGER NOT NULL,
    `key`           VARCHAR(256) NOT NULL,
    `value`         VARCHAR(256),
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`pid`, `key`)
)ENGINE=innodb DEFAULT CHARSET=utf8;

UPDATE db_version SET version = '6.2.1.10';