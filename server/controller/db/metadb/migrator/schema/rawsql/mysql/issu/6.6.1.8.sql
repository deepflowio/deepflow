CREATE TABLE IF NOT EXISTS license_func_log (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    team_id                 INTEGER DEFAULT 1,
    agent_name              VARCHAR(256) NOT NULL,
    agent_id                INTEGER NOT NULL,
    user_id                 INTEGER NOT NULL,
    license_function        INTEGER NOT NULL COMMENT '1.traffic distribution 2.network monitoring 3.call monitoring 4.function monitoring 5.application monitoring 6.indicator monitoring 7.database monitoring 8.log monitoring 9.max',
    enabled                 INTEGER NOT NULL COMMENT '0.false 1.true',
    created_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;


DROP PROCEDURE IF EXISTS update_vtaps;
CREATE PROCEDURE update_vtaps()
BEGIN
    DECLARE current_db_name VARCHAR(255);

    START TRANSACTION;

    -- check whether current db is default, @defaultDatabaseName variable will be added by code when sql is executed
    SELECT DATABASE() INTO current_db_name;
    IF @defaultDatabaseName = current_db_name THEN
        UPDATE vtap
        SET license_functions = '1,2,3,4,5,6,7,8'
        WHERE EXISTS (
            SELECT 1
            FROM consumer_bill
        ) AND (license_functions IS NULL OR license_functions = '');
    END IF;
    -- do migration in default and non-default dbs
    -- whether default db or not, update db_version to latest, remember update DB_VERSION_EXPECT in migrate/init.go
    UPDATE db_version SET version='6.6.1.8';
    COMMIT; 
END;

CALL update_vtaps();
