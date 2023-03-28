ALTER TABLE lb MODIFY COLUMN TEXT COMMENT 'separated by ,';

UPDATE db_version SET version = '6.2.1.24';
