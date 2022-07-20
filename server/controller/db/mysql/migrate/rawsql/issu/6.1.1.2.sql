USE deepflow;

ALTER TABLE
    go_genesis_host
ADD
    node_ip CHAR(48) DEFAULT NULL;

ALTER TABLE
    go_genesis_ip
ADD
    node_ip CHAR(48) DEFAULT NULL;

ALTER TABLE
    go_genesis_lldp
ADD
    node_ip CHAR(48) DEFAULT NULL;

ALTER TABLE
    go_genesis_network
ADD
    node_ip CHAR(48) DEFAULT NULL;

ALTER TABLE
    go_genesis_port
ADD
    node_ip CHAR(48) DEFAULT NULL;

ALTER TABLE
    go_genesis_vinterface
ADD
    node_ip CHAR(48) DEFAULT NULL;

ALTER TABLE
    go_genesis_vm
ADD
    node_ip CHAR(48) DEFAULT NULL;

ALTER TABLE
    go_genesis_vpc
ADD
    node_ip CHAR(48) DEFAULT NULL;