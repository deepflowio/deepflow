
CREATE TABLE IF NOT EXISTS biz_decode_dictionary (
    id                     INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    team_id                INTEGER DEFAULT 1,
    name                   VARCHAR(256) NOT NULL,
    yaml                   TEXT,
    created_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

CREATE TABLE IF NOT EXISTS biz_decode_policy (
    id                     INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    team_id                INTEGER DEFAULT 1,
    name                   VARCHAR(256) NOT NULL,
    yaml                   TEXT,
    created_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

CREATE TABLE IF NOT EXISTS biz_decode_policy_field (
    id                     INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    policy_id              INTEGER NOT NULL,
    name                   VARCHAR(256) NOT NULL,
    yaml                   TEXT,
    created_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

CREATE TABLE IF NOT EXISTS biz_decode_dictionary_policy_field_connection (
    id                     INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    dictionary_id          INTEGER NOT NULL,
    policy_field_id        INTEGER NOT NULL,
    policy_field_node_path VARCHAR(512) NOT NULL,
    created_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

CREATE TABLE IF NOT EXISTS biz_decode_policy_agent_group_connection (
    id                     INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    policy_id              INTEGER NOT NULL,
    agent_group_id         INTEGER NOT NULL,
    created_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- Update DB version
UPDATE db_version SET version='7.1.0.24';
