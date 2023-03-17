ALTER TABLE pod_service ADD COLUMN label TEXT COMMENT 'separated by ,';

UPDATE db_version SET version = '6.2.1.20';
