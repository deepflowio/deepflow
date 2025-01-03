START TRANSACTION;

TRUNCATE go_genesis_host;

TRUNCATE go_genesis_ip;

TRUNCATE go_genesis_lldp;

TRUNCATE go_genesis_network;

TRUNCATE go_genesis_port;

TRUNCATE go_genesis_vinterface;

TRUNCATE go_genesis_vm;

TRUNCATE go_genesis_vpc;

UPDATE
    db_version
SET
    version = '6.1.1.11';

COMMIT;
