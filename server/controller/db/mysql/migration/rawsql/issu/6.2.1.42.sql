ALTER TABLE domain_additional_resource ADD COLUMN compressed_content LONGBLOB NOT NULL AFTER `content`;

UPDATE db_version SET version='6.2.1.42';
