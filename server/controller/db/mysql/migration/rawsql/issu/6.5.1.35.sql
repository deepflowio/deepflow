DROP PROCEDURE IF EXISTS HandleDistinguishDB;

CREATE PROCEDURE HandleDistinguishDB()
BEGIN
    DECLARE current_db_name VARCHAR(255);

    -- check whether current db is default, @defaultDatabaseName variable will be added by code when sql is executed
    SELECT DATABASE() INTO current_db_name;
    IF @defaultDatabaseName = current_db_name THEN
        CREATE TABLE IF NOT EXISTS only_default_db (
            `id`              INTEGER NOT NULL PRIMARY KEY,
            `name`            VARCHAR(256),
            `user_id`         INTEGER,
            `team_id`         INTEGER DEFAULT 1,
            `updated_at`      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )ENGINE=innodb DEFAULT CHARSET=utf8;
    END IF;
    CREATE TABLE IF NOT EXISTS all_dbs (
        `id`              INTEGER NOT NULL PRIMARY KEY,
        `name`            VARCHAR(256),
        `user_id`         INTEGER,
        `team_id`         INTEGER DEFAULT 1,
        `updated_at`      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )ENGINE=innodb DEFAULT CHARSET=utf8;
    -- do migration in default and non-default dbs
END;

CALL HandleDistinguishDB();
DROP PROCEDURE HandleDistinguishDB;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.5.1.35';
-- modify end
