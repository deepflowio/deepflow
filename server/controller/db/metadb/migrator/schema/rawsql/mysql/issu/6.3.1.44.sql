CREATE TABLE IF NOT EXISTS mail_server (
id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
status                  int NOT NULL ,
host                    TEXT NOT NULL,
port                    int Not NULL,
user                    TEXT NOT NULL,
password                TEXT NOT NULL,
security                TEXT Not NULL,
lcuuid                  CHAR(64) DEFAULT ''
)ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;

UPDATE db_version SET version='6.3.1.44';
