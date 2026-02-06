CREATE TABLE IF NOT EXISTS silence_policy (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    team_id                 INTEGER DEFAULT 1,
    user_id                 INTEGER,
    name                    CHAR(128) NOT NULL,
    description             VARCHAR(256) DEFAULT '',
    type                    TINYINT DEFAULT 0 COMMENT '0-only once 1-duplicate',
    created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    start_time              TIMESTAMP,
    end_time                TIMESTAMP,
    expired_time            TIMESTAMP,
    cycle_config            TEXT,
    lcuuid                  CHAR(64)
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;

CREATE TABLE IF NOT EXISTS alarm_silence (
    id                       INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    alarm_policy_lcuuid      CHAR(64) NOT NULL,
    silence_policy_lcuuid    CHAR(64) NOT NULL,
    UNIQUE (alarm_policy_lcuuid, silence_policy_lcuuid)
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;

-- Update DB version
UPDATE db_version SET version='6.6.1.65';
