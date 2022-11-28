
CREATE TABLE IF NOT EXISTS ch_int_enum (
    tag_name                VARCHAR(256) NOT NULL,
    value                   INTEGER NOT NULL,
    name                    VARCHAR(256) ,
    PRIMARY KEY  (tag_name,value)
)ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;

UPDATE db_version SET version = '6.1.3.3';