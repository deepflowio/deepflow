CREATE TABLE IF NOT EXISTS dial_test_task (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                    VARCHAR(256) NOT NULL,
    protocol                INTEGER NOT NULL COMMENT '1.ICMP',
    host                    VARCHAR(256) NOT NULL COMMENT 'dial test address',
    overtime_time           INTEGER DEFAULT 2000 COMMENT 'unit: ms',
    payload                 INTEGER DEFAULT 64,
    ttl                     SMALLINT DEFAULT 64,
    dial_location           VARCHAR(256) NOT NULL,
    dial_frequency          INTEGER DEFAULT 1000 COMMENT 'unit: ms',
    pcap                    MEDIUMBLOB,
    created_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE dial_test_task;

UPDATE db_version SET version = '6.2.1.0';
