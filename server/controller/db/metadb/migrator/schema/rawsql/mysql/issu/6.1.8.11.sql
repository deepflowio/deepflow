START TRANSACTION;

DELETE FROM vtap_group_configuration WHERE vtap_group_lcuuid NOT IN (SELECT lcuuid FROM vtap_group);

UPDATE db_version SET version = '6.1.8.11';

COMMIT;
