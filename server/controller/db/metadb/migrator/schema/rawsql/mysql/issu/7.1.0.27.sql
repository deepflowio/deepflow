CREATE TABLE IF NOT EXISTS biz_decode_custom_protocol (
    id                     INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    team_id                INTEGER DEFAULT 1,
    name                   VARCHAR(256) NOT NULL,
    yaml                   MEDIUMTEXT,
    created_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

CREATE TABLE IF NOT EXISTS biz_decode_custom_protocol_policy_connection (
    id                     INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    custom_protocol_id     INTEGER NOT NULL,
    policy_id              INTEGER NOT NULL,
    created_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

DROP TABLE IF EXISTS biz_decode_custom_protocol_policy_connection;

-- Update DB version
UPDATE db_version SET version='7.1.0.27';
