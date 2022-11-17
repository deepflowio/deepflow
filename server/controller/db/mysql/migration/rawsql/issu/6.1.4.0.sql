ALTER TABLE vtap ADD COLUMN region CHAR(64) DEFAULT '' AFTER az;

UPDATE db_version SET version = '6.1.4.0';
