ALTER TABLE ch_int_enum MODIFY COLUMN value INTEGER DEFAULT 0;

UPDATE db_version SET version = '6.1.3.4';
