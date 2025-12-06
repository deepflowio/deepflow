CREATE TABLE IF NOT EXISTS agent_group_configuration_changelog (
    id                              INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    agent_group_configuration_id    INTEGER NOT NULL,
    user_id                         INTEGER NOT NULL,
    remarks                         TEXT NOT NULL,
    yaml_diff                       MEDIUMTEXT NOT NULL,
    lcuuid                          CHAR(64) NOT NULL,
    created_at                      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                      TIMESTAMP NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE agent_group_configuration_changelog;

UPDATE db_version SET version='7.1.0.15';
