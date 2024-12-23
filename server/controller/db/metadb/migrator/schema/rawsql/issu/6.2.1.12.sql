ALTER TABLE domain MODIFY COLUMN cluster_id VARCHAR(64) DEFAULT '';
ALTER TABLE sub_domain MODIFY COLUMN cluster_id VARCHAR(64) DEFAULT '';

UPDATE db_version SET version = '6.2.1.12';
