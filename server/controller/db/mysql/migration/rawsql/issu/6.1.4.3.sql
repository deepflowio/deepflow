
ALTER TABLE vtap MODIFY COLUMN revision VARCHAR(256);

UPDATE db_version SET version = '6.1.4.3';
