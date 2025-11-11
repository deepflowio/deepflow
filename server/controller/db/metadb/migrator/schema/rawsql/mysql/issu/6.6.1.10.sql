DROP TABLE IF EXISTS ch_vtap;

CREATE TABLE IF NOT EXISTS ch_vtap (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    type                    INTEGER,
    team_id                 INTEGER,
    host_id                 INTEGER,
    host_name               VARCHAR(256),
    chost_id                INTEGER,
    chost_name              VARCHAR(256),
    pod_node_id             INTEGER,
    pod_node_name           VARCHAR(256),
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

-- whether default db or not, update db_version to latest, remember update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.6.1.10';
-- modify end
