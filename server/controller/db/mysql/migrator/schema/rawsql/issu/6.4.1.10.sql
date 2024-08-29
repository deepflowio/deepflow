-- delete invalid table
DROP TABLE IF EXISTS `genesis_host`;
DROP TABLE IF EXISTS `genesis_ip`;
DROP TABLE IF EXISTS `genesis_lldp`;
DROP TABLE IF EXISTS `genesis_network`;
DROP TABLE IF EXISTS `genesis_port`;
DROP TABLE IF EXISTS `genesis_vinterface`;
DROP TABLE IF EXISTS `genesis_vm`;
DROP TABLE IF EXISTS `genesis_vpc`;

-- rename genesis storage table
ALTER TABLE `go_genesis_storage` RENAME TO `genesis_storage`;

-- delete go genesis table
DROP TABLE IF EXISTS `go_genesis_host`;
DROP TABLE IF EXISTS `go_genesis_ip`;
DROP TABLE IF EXISTS `go_genesis_lldp`;
DROP TABLE IF EXISTS `go_genesis_network`;
DROP TABLE IF EXISTS `go_genesis_port`;
DROP TABLE IF EXISTS `go_genesis_process`;
DROP TABLE IF EXISTS `go_genesis_vinterface`;
DROP TABLE IF EXISTS `go_genesis_vip`;
DROP TABLE IF EXISTS `go_genesis_vm`;
DROP TABLE IF EXISTS `go_genesis_vpc`;

-- create new genesis table
CREATE TABLE `genesis_host` (
    lcuuid      CHAR(64),
    hostname    VARCHAR(256),
    ip          CHAR(64),
    vtap_id     INTEGER,
    node_ip     CHAR(48),
    PRIMARY KEY (`lcuuid`,`vtap_id`, `node_ip`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4;

CREATE TABLE `genesis_vm` (
    lcuuid          CHAR(64),
    name            VARCHAR(256),
    label           CHAR(64),
    vpc_lcuuid      CHAR(64),
    launch_server   CHAR(64),
    node_ip         CHAR(48),
    state           INTEGER,
    vtap_id         INTEGER,
    created_at      DATETIME,
    PRIMARY KEY (`lcuuid`,`vtap_id`, `node_ip`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4;

CREATE TABLE `genesis_vip` (
    lcuuid      CHAR(64),
    ip          CHAR(64),
    vtap_id     INTEGER,
    node_ip     CHAR(48),
    PRIMARY KEY (`lcuuid`,`vtap_id`, `node_ip`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4;

CREATE TABLE `genesis_vpc` (
    lcuuid          CHAR(64),
    node_ip         CHAR(48),
    vtap_id         INTEGER,
    name            VARCHAR(256),
    PRIMARY KEY (`lcuuid`,`vtap_id`, `node_ip`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4;

CREATE TABLE `genesis_network` (
    name            VARCHAR(256),
    lcuuid          CHAR(64),
    segmentation_id INTEGER,
    net_type        INTEGER,
    external        TINYINT(1),
    vpc_lcuuid      CHAR(64),
    vtap_id         INTEGER,
    node_ip         CHAR(48),
    PRIMARY KEY (`lcuuid`,`vtap_id`, `node_ip`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4;

CREATE TABLE `genesis_port` (
    lcuuid          CHAR(64),
    type            INTEGER,
    device_type     INTEGER,
    mac             CHAR(32),
    device_lcuuid   CHAR(64),
    network_lcuuid  CHAR(64),
    vpc_lcuuid      CHAR(64),
    vtap_id         INTEGER,
    node_ip         CHAR(48),
    PRIMARY KEY (`lcuuid`,`vtap_id`, `node_ip`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4;

CREATE TABLE `genesis_ip` (
    lcuuid              CHAR(64),
    ip                  CHAR(64),
    vinterface_lcuuid   CHAR(64),
    node_ip             CHAR(48),
    last_seen           DATETIME,
    vtap_id             INTEGER,
    masklen             INTEGER DEFAULT 0,
    PRIMARY KEY (`lcuuid`,`vtap_id`, `node_ip`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4;

CREATE TABLE `genesis_lldp` (
    lcuuid                  CHAR(64),
    host_ip                 CHAR(48),
    host_interface          CHAR(64),
    node_ip                 CHAR(48),
    system_name             VARCHAR(512),
    management_address      VARCHAR(512),
    vinterface_lcuuid       VARCHAR(512),
    vinterface_description  VARCHAR(512),
    vtap_id                 INTEGER,
    last_seen               DATETIME,
    PRIMARY KEY (`lcuuid`,`vtap_id`, `node_ip`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4;

CREATE TABLE `genesis_vinterface` (
    netns_id              INTEGER UNSIGNED DEFAULT 0,
    lcuuid                CHAR(64),
    name                  CHAR(64),
    mac                   CHAR(32),
    ips                   TEXT,
    tap_name              CHAR(64),
    tap_mac               CHAR(32),
    device_lcuuid         CHAR(64),
    device_name           VARCHAR(512),
    device_type           CHAR(64),
    if_type               CHAR(64) DEFAULT '',
    host_ip               CHAR(48),
    node_ip               CHAR(48),
    last_seen             DATETIME,
    vtap_id               INTEGER,
    kubernetes_cluster_id CHAR(64),
    PRIMARY KEY (`lcuuid`,`vtap_id`, `node_ip`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4;

CREATE TABLE `genesis_process` (
    netns_id            INTEGER UNSIGNED DEFAULT 0,
    vtap_id             INTEGER NOT NULL DEFAULT 0,
    pid                 INTEGER NOT NULL,
    lcuuid              CHAR(64) DEFAULT '',
    name                TEXT,
    process_name        TEXT,
    cmd_line            TEXT,
    user                VARCHAR(256) DEFAULT '',
    container_id        CHAR(64) DEFAULT '',
    os_app_tags         TEXT COMMENT 'separated by ,',
    node_ip             CHAR(48) DEFAULT '',
    start_time          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`lcuuid`,`vtap_id`, `node_ip`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

UPDATE db_version SET version='6.4.1.10';
