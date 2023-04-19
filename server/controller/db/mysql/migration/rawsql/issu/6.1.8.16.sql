ALTER TABLE pod_service ADD COLUMN label TEXT COMMENT 'separated by ,';

UPDATE db_version SET version='6.1.8.16';
