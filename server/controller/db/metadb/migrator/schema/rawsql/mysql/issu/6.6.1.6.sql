DROP TABLE IF EXISTS ch_vtap_port;

CREATE TABLE IF NOT EXISTS ch_vtap_port (
    vtap_id                 INTEGER NOT NULL,
    tap_port                BIGINT NOT NULL,
    name                    VARCHAR(256),
    mac_type                INTEGER DEFAULT 1 COMMENT '1:tap_mac,2:mac',
    host_id                 INTEGER,
    host_name               VARCHAR(256),
    chost_id                INTEGER,
    chost_name              VARCHAR(256),
    pod_node_id             INTEGER,
    pod_node_name           VARCHAR(256),
    device_type             INTEGER,
    device_id               INTEGER,
    device_name             VARCHAR(256),
    icon_id                 INTEGER,
    team_id                 INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (vtap_id, tap_port)
)ENGINE=innodb DEFAULT CHARSET=utf8;

-- whether default db or not, update db_version to latest, remember update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.6.1.6';
-- modify end
