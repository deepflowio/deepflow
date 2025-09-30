START TRANSACTION;

DELETE FROM vtap_group_configuration WHERE vtap_group_lcuuid IS NULL;
DELETE FROM vtap_group_configuration WHERE vtap_group_lcuuid="";

UPDATE db_version SET version = '6.1.3.5';

COMMIT;
