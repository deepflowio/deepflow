ALTER TABLE domain_additional_resource MODIFY COLUMN content LONGTEXT;

UPDATE db_version SET version = '6.2.1.22';
