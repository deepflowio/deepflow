
ALTER TABLE domain_additional_resource MODIFY content MEDIUMTEXT;

UPDATE db_version SET version = '6.1.8.10';
