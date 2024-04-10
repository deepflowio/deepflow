DROP TABLE IF EXISTS ch_lb_listener;
DROP TABLE IF EXISTS ch_ip_relation;

CREATE TABLE IF NOT EXISTS ch_lb_listener (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    team_id                 INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_ip_relation (
    l3_epc_id           INTEGER NOT NULL,
    ip                  CHAR(64) NOT NULL,
    natgw_id            INTEGER,
    natgw_name          VARCHAR(256),
    lb_id               INTEGER,
    lb_name             VARCHAR(256),
    lb_listener_id      INTEGER,
    lb_listener_name    VARCHAR(256),
    pod_ingress_id      INTEGER,
    pod_ingress_name    VARCHAR(256),
    pod_service_id      INTEGER,
    pod_service_name    VARCHAR(256),
    team_id             INTEGER,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (l3_epc_id, ip)
)ENGINE=innodb DEFAULT CHARSET=utf8;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.5.1.18';
-- modify end

