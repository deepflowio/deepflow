CREATE TABLE IF NOT EXISTS ch_statistic_tag (
    `db`                      VARCHAR(128) NOT NULL,
    `table`                   VARCHAR(256) NOT NULL,
    `type`                    VARCHAR(128) NOT NULL,
    `name`                    VARCHAR(256) NOT NULL,
    `updated_at`              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    PRIMARY KEY (`db`, `table`, `type`, `name`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_statistic_tag;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/version.go
UPDATE db_version SET version='6.6.1.13';
-- modify end