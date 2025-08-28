START TRANSACTION;

UPDATE vtap_group_configuration SET collector_socket_type=NULL WHERE collector_socket_type="UDP";
UPDATE vtap_group_configuration SET compressor_socket_type=NULL WHERE compressor_socket_type="UDP" or compressor_socket_type="RAW_UDP";

UPDATE db_version SET version = '6.2.1.14';

COMMIT;
