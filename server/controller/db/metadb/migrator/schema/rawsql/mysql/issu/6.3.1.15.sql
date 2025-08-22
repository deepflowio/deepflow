-- add to v6.2
-- ALTER TABLE domain_additional_resource ADD COLUMN compressed_content LONGBLOB AFTER `content`;

UPDATE db_version SET version='6.3.1.15';
