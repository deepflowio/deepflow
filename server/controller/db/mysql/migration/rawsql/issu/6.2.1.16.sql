CREATE TABLE IF NOT EXISTS repo_agent (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    arch                VARCHAR(256) DEFAULT '',
    os                  VARCHAR(256) DEFAULT '',
    branch              VARCHAR(256) DEFAULT '',
    rev_count           VARCHAR(256) DEFAULT '',
    git_hash            VARCHAR(256) DEFAULT '',
    process_name        VARCHAR(256) NOT NULL,
    image               LONGBLOB NOT NULL,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;

UPDATE db_version SET version = '6.2.1.16';
