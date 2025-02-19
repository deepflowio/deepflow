CREATE TABLE IF NOT EXISTS custom_service (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(128) NOT NULL,
    team_id             INTEGER DEFAULT 1,
    type                INTEGER DEFAULT 0 COMMENT '0: unknown 1: IP 2: PORT',
    resource            TEXT DEFAULT '',
    epc_id              INTEGER DEFAULT 0,
    domain_id           INTEGER DEFAULT 0,
    domain              CHAR(64) DEFAULT '' COMMENT 'reserved for backend',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE INDEX name_index(name)
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;

UPDATE db_version SET version='7.0.1.9';
