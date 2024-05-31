
CREATE TABLE IF NOT EXISTS ch_user (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;


-- whether default db or not, update db_version to latest, remember update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.5.1.39';
-- modify end
