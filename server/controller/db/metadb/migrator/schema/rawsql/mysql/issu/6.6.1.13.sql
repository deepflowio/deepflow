-- modify start, add upgrade sql
DROP PROCEDURE IF EXISTS CreateTableIfNotExists;

CREATE PROCEDURE CreateTableIfNotExists()
BEGIN
    DECLARE table_count INT;

    -- 检查表是否存在
    SELECT COUNT(*)
    INTO table_count
    FROM information_schema.tables
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'agent_group_configuration';

    -- 如果表不存在，则创建表
    IF table_count = 0 THEN
        CREATE TABLE agent_group_configuration (
            id    INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
            lcuuid CHAR(64) NOT NULL,
            agent_group_lcuuid CHAR(64) NOT NULL,
            yaml   TEXT,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
    END IF;
END;

CALL CreateTableIfNotExists();

DROP PROCEDURE CreateTableIfNotExists;

-- update db_version to latest, remember to update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.6.1.13';
-- modify end

