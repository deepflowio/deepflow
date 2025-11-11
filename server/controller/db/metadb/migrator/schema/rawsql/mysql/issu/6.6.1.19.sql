DROP TABLE IF EXISTS ch_string_enum;
DROP TABLE IF EXISTS ch_int_enum;

CREATE TABLE IF NOT EXISTS ch_string_enum (
    tag_name                VARCHAR(256) NOT NULL ,
    value                   VARCHAR(256) NOT NULL,
    name_zh                 VARCHAR(256) ,
    name_en                 VARCHAR(256) ,
    description_zh          VARCHAR(256) ,
    description_en          VARCHAR(256) ,
    updated_at              DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY  (tag_name,value)
)ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_int_enum (
    tag_name                VARCHAR(256) NOT NULL,
    value                   INTEGER DEFAULT 0,
    name_zh                 VARCHAR(256) ,
    name_en                 VARCHAR(256) ,
    description_zh          VARCHAR(256) ,
    description_en          VARCHAR(256) ,
    updated_at              DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY  (tag_name,value)
)ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.6.1.19';
-- modify end

