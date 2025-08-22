DROP TABLE IF EXISTS ch_vtap;
DROP TABLE IF EXISTS ch_vtap_port;

CREATE TABLE IF NOT EXISTS ch_vtap (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    type                    INTEGER,
    icon_id                 INTEGER,
    team_id                 INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_vtap_port (
    vtap_id                 INTEGER NOT NULL,
    tap_port                BIGINT NOT NULL,
    name                    VARCHAR(256),
    mac_type                INTEGER DEFAULT 1 COMMENT '1:tap_mac,2:mac',
    host_id                 INTEGER,
    host_name               VARCHAR(256),
    device_type             INTEGER,
    device_id               INTEGER,
    device_name             VARCHAR(256),
    icon_id                 INTEGER,
    team_id                 INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (vtap_id, tap_port)
)ENGINE=innodb DEFAULT CHARSET=utf8;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.5.1.20';
-- modify end
