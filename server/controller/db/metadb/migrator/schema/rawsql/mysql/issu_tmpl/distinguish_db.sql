DROP PROCEDURE IF EXISTS HandleDistinguishDB;

CREATE PROCEDURE HandleDistinguishDB(
    IN tableName VARCHAR(255),
    IN colName VARCHAR(255),
    IN colType VARCHAR(255),
    IN defaultVal VARCHAR(255),
    IN afterCol VARCHAR(255)
)
BEGIN
    DECLARE current_db_name VARCHAR(255);

    -- check whether current db is default, @defaultDatabaseName variable will be added by code when sql is executed
    SELECT DATABASE() INTO current_db_name;
    IF @defaultDatabaseName = current_db_name THEN
        -- do migration in default db
    END IF;
    -- do migration in default and non-default dbs
END;

CALL HandleDistinguishDB('vl2_net', 'domain', 'CHAR(64)', '""', 'sub_domain');
CALL HandleDistinguishDB('domain', 'team_id', 'INTEGER', '1', 'id');

DROP PROCEDURE HandleDistinguishDB;

-- whether default db or not, update db_version to latest, remember update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.5.1.15';
-- modify end
