CREATE TABLE IF NOT EXISTS ch_policy (
    `tunnel_type`      INTEGER NOT NULL,
    `acl_gid`          INTEGER NOT NULL,
    `id`               INTEGER,
    `name`             VARCHAR(256),
    `updated_at`       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`tunnel_type`, `acl_gid`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_policy;

CREATE TABLE IF NOT EXISTS ch_npb_tunnel (
    `id`              INTEGER NOT NULL PRIMARY KEY,
    `name`            VARCHAR(256),
    `updated_at`      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_npb_tunnel;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/version.go
UPDATE db_version SET version='6.5.1.4';
-- modify end
