ALTER TABLE lb MODIFY COLUMN vip TEXT COMMENT 'separated by ,';

UPDATE db_version SET version = '6.2.1.24';
