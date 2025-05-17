CREA TE TABLE IF NOT EXISTS plugin (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(256) NOT NULL,
    type                INTEGER NOT NULL COMMENT '1: wasm 2: so 3: lua',
    user_name           INTEGER NOT NULL DEFAULT 1 COMMENT '1: agent 2: server',
    image               LONGBLOB NOT NULL,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE INDEX name_index(name)
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COMMENT='store plugins for sending to vtap';
TRUNCATE TABLE plugin;
