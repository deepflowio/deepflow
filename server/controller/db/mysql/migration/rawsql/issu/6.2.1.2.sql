ALTER TABLE vm ADD COLUMN cloud_tags TEXT COMMENT 'separated by ,' AFTER launch_server;

CREATE TABLE IF NOT EXISTS go_genesis_process (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    vtap_id             INTEGER NOT NULL DEFAULT 0,
    pid                 INTEGER NOT NULL,
    lcuuid              CHAR(64) DEFAULT '',
    name                VARCHAR(256) DEFAULT '',
    process_name        VARCHAR(256) DEFAULT '',
    cmd_line            TEXT,
    user                VARCHAR(256) DEFAULT '',
    os_app_tags         TEXT COMMENT 'separated by ,',
    node_ip             CHAR(48) DEFAULT '',
    start_time          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE go_genesis_process;

UPDATE db_version SET version = '6.2.1.2';
