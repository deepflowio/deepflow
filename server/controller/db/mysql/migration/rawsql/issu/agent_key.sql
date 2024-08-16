CREATE TABLE IF NOT EXISTS agent_key (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    agent_id            INTEGER,
    status              INTEGER DEFAULT 0,
    value               blob,
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;

-- update db_version to latest, remember update DB_VERSION_EXPECTED in migration/version.go
UPDATE db_version SET version='6.6.1.9';
-- modify end

COMMIT;
