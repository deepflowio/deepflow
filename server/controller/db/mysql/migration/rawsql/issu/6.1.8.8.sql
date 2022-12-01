START TRANSACTION;

DELETE FROM ch_device_port;
DELETE FROM ch_pod_node_port;
DELETE FROM ch_pod_group_port;
DELETE FROM ch_pod_port;
DELETE FROM ch_ip_port;
UPDATE db_version SET version='6.1.8.8';

COMMIT;
