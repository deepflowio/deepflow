CREATE TABLE IF NOT EXISTS db_version (
    version             CHAR(64),
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE db_version;

CREATE TABLE IF NOT EXISTS vtap_repo (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                CHAR(64),
    arch                VARCHAR(256) DEFAULT '',
    os                  VARCHAR(256) DEFAULT '',
    branch              VARCHAR(256) DEFAULT '',
    rev_count           VARCHAR(256) DEFAULT '',
    commit_id           VARCHAR(256) DEFAULT '',
    image               LONGBLOB NOT NULL,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COMMENT='store deepflow-agent for easy upgrade';
TRUNCATE TABLE vtap_repo;

CREATE TABLE IF NOT EXISTS resource_event (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    domain              CHAR(64) DEFAULT '',
    sub_domain          CHAR(64) DEFAULT '',
    resource_lcuuid     CHAR(64) DEFAULT '',
    content             TEXT,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE resource_event;

CREATE TABLE IF NOT EXISTS domain_additional_resource (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    domain              CHAR(64) DEFAULT '',
    content             MEDIUMTEXT,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE domain_additional_resource;

CREATE TABLE IF NOT EXISTS process (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    vtap_id             INTEGER NOT NULL DEFAULT 0,
    pid                 INTEGER NOT NULL,
    process_name        VARCHAR(256) DEFAULT '',
    command_line        TEXT,
    user_name           VARCHAR(256) DEFAULT '',
    start_time          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    os_app_tags         TEXT COMMENT 'separated by ,',
    sub_domain          CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE process;

CREATE TABLE IF NOT EXISTS host_device (
    id                  INTEGER NOT NULL AUTO_INCREMENT,
    type                INTEGER COMMENT '1.Server 3.Gateway 4.DFI',
    state               INTEGER COMMENT '0.Temp 1.Creating 2.Complete 3.Modifying 4.Exception',
    name                VARCHAR(256) DEFAULT '',
    alias               CHAR(64) DEFAULT '',
    description         VARCHAR(256) DEFAULT '',
    ip                  CHAR(64) DEFAULT '',
    htype               INTEGER COMMENT '1. Xen host 2. VMware host 3. KVM host 4. Public cloud host 5. Hyper-V',
    create_method       INTEGER DEFAULT 0 COMMENT '0.learning 1.user_defined',
    user_name           VARCHAR(64) DEFAULT '',
    user_passwd         VARCHAR(64) DEFAULT '',
    vcpu_num            INTEGER DEFAULT 0,
    mem_total           INTEGER DEFAULT 0 COMMENT 'unit: M',
    rack                VARCHAR(64),
    rackid              INTEGER,
    topped              INTEGER DEFAULT 0,
    az                  CHAR(64) DEFAULT '',
    region              CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    extra_info          TEXT,
    lcuuid              CHAR(64) DEFAULT '',
    synced_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL,
    PRIMARY KEY (id,domain)
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE host_device;

CREATE TABLE IF NOT EXISTS third_party_device (
    id                  INTEGER NOT NULL AUTO_INCREMENT,
    epc_id              INTEGER DEFAULT 0,
    vm_id               INTEGER,
    curr_time           TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sys_uptime          CHAR(32),
    type                INTEGER COMMENT '1.VM 2.Gateway 3.Compute 4.Network 5.Storage 6.Security',
    state               INTEGER COMMENT '0.Temp 1.run 2.stop 3.added to vdc 4.no add to vdc 5.to start 6.to stop',
    errno               INTEGER DEFAULT 0 COMMENT '1.Operate, 2.Install, 3.Uninstall, 4.Status',
    name                varchar(256),
    label               CHAR(64),
    poolid              INTEGER DEFAULT 0,
    community           VARCHAR(256),
    mgmt_ip             CHAR(64),
    data_ip             CHAR(64),
    ctrl_ip             CHAR(64),
    ctrl_mac            CHAR(32),
    data1_mac           CHAR(32),
    data2_mac           CHAR(32),
    data3_mac           CHAR(32),
    launch_server       CHAR(64),
    user_name           VARCHAR(64),
    user_passwd         VARCHAR(64),
    vnc_port            INTEGER DEFAULT 0,
    brand               VARCHAR(64),
    sys_os              VARCHAR(64),
    mem_size            INTEGER COMMENT 'Unit: MB',
    mem_used            INTEGER COMMENT 'Unit: MB',
    mem_usage           VARCHAR(32),
    mem_data            VARCHAR(256),
    cpu_type            VARCHAR(128),
    cpu_num             INTEGER,
    cpu_data            VARCHAR(256),
    disk_size           INTEGER COMMENT 'Unit: GB',
    dsk_num             INTEGER,
    disk_info           VARCHAR(1024),
    nic_num             INTEGER,
    nic_data            VARCHAR(256),
    rack_name           VARCHAR(256),
    userid              INTEGER,
    domain              CHAR(64),
    region              CHAR(64),
    lcuuid              CHAR(64),
    order_id            INTEGER,
    product_specification_lcuuid CHAR(64),
    role                INTEGER DEFAULT 1 COMMENT '1. General Purpose, 2. Load Balancer, 3. Database, 4. Web Server, 5. APP Server, 6. Firewall, 7. Gateway, 8. VPN, 9. Storage, 10. WAF 13.DEEPFLOW_TOOL',
    create_time         DATETIME,
    gateway             CHAR(64) DEFAULT '' COMMENT 'gateway of the default route',
    raid_support        CHAR(64) DEFAULT '' COMMENT 'must be a subset of RAID 0, 1, 5, 6, 10, 50, 60',
    PRIMARY KEY (id,domain)
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE third_party_device;

CREATE TABLE IF NOT EXISTS vnet(
    id                  INTEGER NOT NULL AUTO_INCREMENT,
    state               INTEGER NOT NULL COMMENT '0.Temp 1.Creating 2.Created 3.Exception 4.Modifing 5.Destroying 6.To run 7.Running 8.To stop 9.Stopped',
    name                varchar(256) DEFAULT '',
    label               CHAR(64) DEFAULT '',
    description         VARCHAR(256) DEFAULT '',
    epc_id              INTEGER DEFAULT 0,
    gw_launch_server    CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    region              CHAR(64) DEFAULT '',
    az                  CHAR(64) DEFAULT '',
    userid              INTEGER,
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL,
    PRIMARY KEY (id,domain),
    INDEX state_server_index(state, gw_launch_server)
)ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=256 /* reset in init_auto_increment */;
DELETE FROM vnet;

CREATE TABLE IF NOT EXISTS routing_table (
    id                  INTEGER NOT NULL auto_increment PRIMARY KEY,
    vnet_id             INTEGER,
    destination         TEXT,
    nexthop_type        TEXT,
    nexthop             TEXT,
    lcuuid              CHAR(64)
)engine=innodb AUTO_INCREMENT=1  DEFAULT CHARSET=utf8;
TRUNCATE TABLE routing_table;

CREATE TABLE IF NOT EXISTS security_group (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                varchar(256) DEFAULT '',
    label               varchar(64) DEFAULT '',
    alias               CHAR(64) DEFAULT '',
    epc_id              INTEGER DEFAULT 0,
    domain              CHAR(64) DEFAULT '',
    region              CHAR(64) DEFAULT '',
    topped              INTEGER DEFAULT 0,
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE security_group;

CREATE TABLE IF NOT EXISTS security_group_rule (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    sg_id               INTEGER NOT NULL,
    direction           TINYINT(1) NOT NULL DEFAULT 0 COMMENT '0.Unknow 1.Ingress 2.Egress',
    protocol            CHAR(64) DEFAULT '',
    ethertype           TINYINT(1) NOT NULL DEFAULT 0 COMMENT '0.Unknow 1.IPv4 2.IPv6',
    local_port_range    TEXT,
    remote_port_range   TEXT,
    local               TEXT,
    remote              TEXT,
    priority            INTEGER NOT NULL,
    action              TINYINT(1) NOT NULL DEFAULT 0 COMMENT '0.Unknow 1.Accept 2.Drop',
    lcuuid              CHAR(64) DEFAULT ''
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE security_group_rule;

CREATE TABLE IF NOT EXISTS vm_security_group (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    sg_id               INTEGER NOT NULL,
    vm_id               INTEGER NOT NULL,
    priority            INTEGER NOT NULL,
    lcuuid              CHAR(64) DEFAULT ''
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE vm_security_group;

CREATE TABLE IF NOT EXISTS vl2 (
    id                  INTEGER NOT NULL AUTO_INCREMENT,
    state               INTEGER NOT NULL COMMENT '0.Temp 1.Creating 2.Created 3.Exception 4.Modifing 5.Destroying 6.Destroyed',
    net_type            INTEGER DEFAULT 4 COMMENT '1.CTRL 2.SERVICE 3.WAN 4.LAN',
    name                VARCHAR(256) NOT NULL,
    create_method       INTEGER DEFAULT 0 COMMENT '0.learning 1.user_defined',
    label               VARCHAR(64) DEFAULT '',
    alias               CHAR(64) DEFAULT '',
    description         VARCHAR(256) DEFAULT '',
    sub_domain          CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    region              CHAR(64) DEFAULT '',
    az                  CHAR(64) DEFAULT '',
    isp                 INTEGER DEFAULT 0,
    userid              INTEGER DEFAULT 0,
    epc_id              INTEGER DEFAULT 0,
    segmentation_id     INTEGER DEFAULT 0,
    tunnel_id           INTEGER DEFAULT 0,
    shared              INTEGER DEFAULT 0,
    topped              INTEGER DEFAULT 0,
    is_vip              INTEGER DEFAULT 0,
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL,
    PRIMARY KEY (id,domain),
    UNIQUE INDEX lcuuid_index(lcuuid)
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=4096 /* reset in init_auto_increment */;
DELETE FROM vl2;

CREATE TABLE IF NOT EXISTS vl2_net (
    id                  INTEGER NOT NULL AUTO_INCREMENT,
    prefix              CHAR(64) DEFAULT '',
    netmask             CHAR(64) DEFAULT '',
    vl2id               INTEGER REFERENCES vl2(id),
    net_index           INTEGER DEFAULT 0,
    name                VARCHAR(256) DEFAULT '',
    label               VARCHAR(64) DEFAULT '',
    sub_domain          CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    PRIMARY KEY (id)
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
DELETE FROM vl2_net;

CREATE TABLE IF NOT EXISTS vm (
    id                  INTEGER NOT NULL AUTO_INCREMENT,
    state               INTEGER NOT NULL COMMENT '0.Temp 1.Creating 2.Created 3.To run 4.Running 5.To suspend 6.Suspended 7.To resume 8. To stop 9.Stopped 10.Modifing 11.Exception 12.Destroying',
    name                VARCHAR(256) DEFAULT '',
    alias               CHAR(64) DEFAULT '',
    label               CHAR(64) DEFAULT '',
    create_method       INTEGER DEFAULT 0 COMMENT '0.learning 1.user_defined',
    htype               INTEGER DEFAULT 1 COMMENT '1.vm-c 2.bm-c 3.vm-n 4.bm-n 5.vm-s 6.bm-s',
    launch_server       CHAR(64) DEFAULT '',
    cloud_tags          TEXT COMMENT 'separated by ,',
    epc_id              INTEGER DEFAULT 0,
    domain              CHAR(64) DEFAULT '',
    az                  CHAR(64) DEFAULT '',
    region              CHAR(64) DEFAULT '',
    userid              INTEGER,
    uid                 CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL,
    PRIMARY KEY (id,domain),
    INDEX state_server_index(state, launch_server)
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
DELETE FROM vm;

CREATE TABLE IF NOT EXISTS vinterface (
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    id                  INTEGER NOT NULL AUTO_INCREMENT,
    name                CHAR(64) DEFAULT '',
    ifindex             INTEGER NOT NULL,
    state               INTEGER NOT NULL COMMENT '1. Attached 2.Detached 3.Exception',
    create_method       INTEGER DEFAULT 0 COMMENT '0.learning 1.user_defined',
    iftype              INTEGER DEFAULT 0 COMMENT '0.Unknown 1.Control 2.Service 3.WAN 4.LAN 5.Trunk 6.Tap 7.Tool',
    mac                 CHAR(32) DEFAULT '',
    tap_mac             CHAR(32) DEFAULT '',
    subnetid            INTEGER DEFAULT 0 COMMENT 'vl2 id',
    vlantag             INTEGER DEFAULT 0,
    devicetype          INTEGER COMMENT 'Type 0.unknown 1.vm 2.vgw 3.third-party-device 4.vmwaf 5.NSP-vgateway 6.host-device 7.network-device 9.DHCP-port 10.pod 11.pod_service 12. redis_instance 13. rds_instance 14. pod_node 15. load_balance 16. nat_gateway',
    deviceid            INTEGER COMMENT 'unknown: Senseless ID, vm: vm ID, vgw/NSP-vgateway: vnet ID, third-party-device: third_party_device ID, vmwaf: vmwaf ID, host-device: host_device ID, network-device: network_device ID',
    sub_domain          CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    region              CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    PRIMARY KEY (id,domain),
    INDEX mac_index(mac)
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
DELETE FROM vinterface;

CREATE TABLE IF NOT EXISTS vinterface_ip (
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    id                  INTEGER NOT NULL AUTO_INCREMENT,
    ip                  CHAR(64) DEFAULT '',
    netmask             CHAR(64) DEFAULT '',
    gateway             CHAR(64) DEFAULT '',
    create_method       INTEGER DEFAULT 0 COMMENT '0.learning 1.user_defined',
    vl2id               INTEGER REFERENCES vl2(id),
    vl2_net_id          INTEGER DEFAULT 0,
    net_index           INTEGER DEFAULT 0,
    sub_domain          CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    vifid               INTEGER REFERENCES vinterface(id),
    isp                 INTEGER DEFAULT 0 COMMENT 'Used for multi-ISP access',
    lcuuid              CHAR(64) DEFAULT '',
    PRIMARY KEY (id)
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
DELETE FROM vinterface_ip;

CREATE TABLE IF NOT EXISTS ip_resource (
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    id                  INTEGER NOT NULL AUTO_INCREMENT,
    ip                  CHAR(64) DEFAULT '',
    alias               CHAR(64) DEFAULT '',
    netmask             INTEGER,
    gateway             CHAR(64) DEFAULT '',
    create_method       INTEGER DEFAULT 0 COMMENT '0.learning 1.user_defined',
    userid              INTEGER DEFAULT 0,
    isp                 INTEGER,
    vifid               INTEGER DEFAULT 0,
    vl2_net_id          INTEGER DEFAULT 0,
    sub_domain          CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    region              CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    PRIMARY KEY (id,domain)
)ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
DELETE FROM ip_resource;

CREATE TABLE IF NOT EXISTS floatingip (
    id                  INTEGER NOT NULL AUTO_INCREMENT,
    domain              CHAR(64) DEFAULT '',
    region              CHAR(64) DEFAULT '',
    epc_id              INTEGER DEFAULT 0,
    vl2_id              INTEGER,
    vm_id               INTEGER,
    ip                  CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    PRIMARY KEY (id,domain)
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE floatingip;

CREATE TABLE IF NOT EXISTS dhcp_port (
    id                  INTEGER NOT NULL AUTO_INCREMENT,
    name                VARCHAR(256) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    region              CHAR(64) DEFAULT '',
    az                  CHAR(64) DEFAULT '',
    userid              INTEGER DEFAULT 0,
    epc_id              INTEGER DEFAULT 0,
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL,
    PRIMARY KEY (id, domain)
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE dhcp_port;

CREATE TABLE IF NOT EXISTS az (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(64) DEFAULT '',
    create_method       INTEGER DEFAULT 0 COMMENT '0.learning 1.user_defined',
    label               VARCHAR(64) DEFAULT '',
    region              CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '' UNIQUE,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL
)ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE az;
INSERT INTO az (id, name, lcuuid, region, domain) values(1, '系统默认', 'ffffffff-ffff-ffff-ffff-ffffffffffff', 'ffffffff-ffff-ffff-ffff-ffffffffffff', 'ffffffff-ffff-ffff-ffff-ffffffffffff');

CREATE TABLE IF NOT EXISTS domain (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(64),
    icon_id             INTEGER,
    display_name        VARCHAR(64) DEFAULT '',
    cluster_id          CHAR(64),
    ip                  VARCHAR(64),
    role                INTEGER DEFAULT 0 COMMENT '1.BSS 2.OSS 3.OpenStack 4.VSphere',
    type                INTEGER DEFAULT 0 COMMENT '1.openstack 2.vsphere 3.nsp 4.tencent 5.filereader 6.aws 7.pingan 8.zstack 9.aliyun 10.huawei prv 11.k8s 12.simulation 13.huawei 14.qingcloud 15.qingcloud_private 16.F5 17.CMB_CMDB 18.azure 19.apsara_stack 20.tencent_tce 21.qingcloud_k8s 22.kingsoft_private 23.genesis 24.microsoft_acs 25.baidu_bce',
    public_ip           VARCHAR(64) DEFAULT NULL,
    config              TEXT,
    error_msg           TEXT,
    enabled             INTEGER NOT NULL DEFAULT '1' COMMENT '0.false 1.true',
    state               INTEGER NOT NULL DEFAULT '1' COMMENT '1.normal 2.deleting 3.exception',
    controller_ip       CHAR(64),
    lcuuid              CHAR(64) DEFAULT '',
    synced_at           DATETIME DEFAULT NULL,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE INDEX lcuuid_index(lcuuid)
)ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE domain;

CREATE TABLE IF NOT EXISTS sub_domain (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    domain              CHAR(64) DEFAULT '',
    name                VARCHAR(64) DEFAULT '',
    display_name        VARCHAR(64) DEFAULT '',
    create_method       INTEGER DEFAULT 0 COMMENT '0.learning 1.user_defined',
    cluster_id          CHAR(64) DEFAULT '',
    config              TEXT,
    error_msg           TEXT,
    enabled             INTEGER NOT NULL DEFAULT '1' COMMENT '0.false 1.true',
    state               INTEGER NOT NULL DEFAULT '1' COMMENT '1.normal 2.deleting 3.exception',
    lcuuid              CHAR(64) DEFAULT '',
    synced_at           DATETIME DEFAULT NULL,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE INDEX lcuuid_index(lcuuid)
)ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE sub_domain;

CREATE TABLE IF NOT EXISTS region (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(64) DEFAULT '',
    create_method       INTEGER DEFAULT 0 COMMENT '0.learning 1.user_defined',
    label               VARCHAR(64) DEFAULT '',
    longitude           DOUBLE(7, 4),
    latitude            DOUBLE(7, 4),
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL,
    UNIQUE INDEX lcuuid_index(lcuuid)
)ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE region;
INSERT INTO region (id, name, lcuuid) values(1, '系统默认', 'ffffffff-ffff-ffff-ffff-ffffffffffff');

CREATE TABLE IF NOT EXISTS az_analyzer_connection (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    az                      CHAR(64) DEFAULT 'ALL',
    region                  CHAR(64) DEFAULT 'ffffffff-ffff-ffff-ffff-ffffffffffff',
    analyzer_ip             CHAR(64),
    lcuuid                  CHAR(64)
)ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE az_analyzer_connection;

CREATE TABLE IF NOT EXISTS az_controller_connection (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    az                      CHAR(64) DEFAULT 'ALL',
    region                  CHAR(64) DEFAULT 'ffffffff-ffff-ffff-ffff-ffffffffffff',
    controller_ip           CHAR(64),
    lcuuid                  CHAR(64)
)ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE az_controller_connection;

CREATE TABLE IF NOT EXISTS sys_configuration (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    param_name          CHAR(64) NOT NULL,
    value               VARCHAR(256),
    comments            TEXT,
    lcuuid              CHAR(64)
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE sys_configuration;
set @lcuuid = (select uuid());
INSERT INTO sys_configuration (`id`,`param_name`, `value`, `comments`, `lcuuid`) VALUES (1, 'cloud_sync_timer', '60', 'unit: s', @lcuuid);
set @lcuuid = (select uuid());
INSERT INTO sys_configuration (`id`,`param_name`, `value`, `comments`, `lcuuid`) VALUES (2, 'pcap_data_retention', '3', 'unit: day', @lcuuid);
set @lcuuid = (select uuid());
INSERT INTO sys_configuration (`id`,`param_name`, `value`, `comments`, `lcuuid`) VALUES (3, 'system_data_retention', '7', 'unit: day', @lcuuid);
set @lcuuid = (select uuid());
INSERT INTO sys_configuration (`id`,`param_name`, `value`, `comments`, `lcuuid`) VALUES (4, 'ntp_servers', '0.cn.pool.ntp.org', '', @lcuuid);

CREATE TABLE IF NOT EXISTS postman_cache(
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    dest                TEXT COMMENT 'destination email address, seprate by ","',
    event_type          INTEGER DEFAULT 0,
    resource_type       INTEGER DEFAULT 0,
    resource_id         INTEGER DEFAULT 0,
    issue_timestamp     INTEGER DEFAULT 0
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE postman_cache;

CREATE TABLE IF NOT EXISTS postman_queue(
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    dest                TEXT COMMENT 'destination email address, seprate by ","',
    aggregate_id        INTEGER DEFAULT 0,
    send_request        TEXT
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE postman_queue;

CREATE TABLE IF NOT EXISTS epc (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    userid              INTEGER DEFAULT 0,
    name                VARCHAR(256) DEFAULT '',
    create_method       INTEGER DEFAULT 0 COMMENT '0.learning 1.user_defined',
    label               VARCHAR(64) DEFAULT '',
    alias               CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    region              CHAR(64) DEFAULT '',
    az                  CHAR(64) DEFAULT '',
    order_id            INTEGER DEFAULT 0,
    tunnel_id           INTEGER DEFAULT 0,
    operationid         INTEGER DEFAULT 0,
    mode                INTEGER DEFAULT 2 COMMENT " 1:route, 2:transparent",
    topped              INTEGER DEFAULT 0,
    cidr                CHAR(64) DEFAULT '',
    uid                 CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '' UNIQUE,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE epc;

CREATE TABLE IF NOT EXISTS peer_connection (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    label               CHAR(64) DEFAULT '',
    local_epc_id        INTEGER DEFAULT 0,
    remote_epc_id       INTEGER DEFAULT 0,
    local_region_id     INTEGER DEFAULT 0,
    remote_region_id    INTEGER DEFAULT 0,
    create_method       INTEGER DEFAULT 0 COMMENT '0.learning 1.user_defined',
    domain              CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE peer_connection;

CREATE TABLE IF NOT EXISTS cen (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    label               CHAR(64) DEFAULT '',
    alias               CHAR(64) DEFAULT '',
    epc_ids             TEXT COMMENT 'separated by ,',
    domain              CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE cen;

CREATE TABLE IF NOT EXISTS nat_gateway (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    label               CHAR(64) DEFAULT '',
    floating_ips        TEXT COMMENT 'separated by ,',
    epc_id              INTEGER DEFAULT 0,
    az                  CHAR(64) DEFAULT '',
    region              CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    uid                 CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE nat_gateway;

CREATE TABLE IF NOT EXISTS nat_rule (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    nat_id              INTEGER DEFAULT 0,
    type                CHAR(16) DEFAULT '',
    protocol            CHAR(64) DEFAULT '',
    floating_ip         CHAR(64) DEFAULT '',
    floating_ip_port    INTEGER DEFAULT NULL,
    fixed_ip            CHAR(64) DEFAULT '',
    fixed_ip_port       INTEGER DEFAULT NULL,
    port_id             INTEGER DEFAULT NULL,
    domain              CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT ''
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE nat_rule;

CREATE TABLE IF NOT EXISTS nat_vm_connection (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    nat_id              INTEGER,
    vm_id               INTEGER,
    domain              CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT ''
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE nat_vm_connection;

CREATE TABLE IF NOT EXISTS redis_instance (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    label               CHAR(64) DEFAULT '',
    state               tinyint(1) NOT NULL DEFAULT 0 COMMENT '0. Unknown 1. Running 2. Recovering',
    domain              CHAR(64) DEFAULT '',
    region              CHAR(64) DEFAULT '',
    az                  CHAR(64) DEFAULT '',
    epc_id              INTEGER DEFAULT 0,
    version             CHAR(64) DEFAULT '',
    internal_host       VARCHAR(128) DEFAULT '',
    public_host         VARCHAR(128) DEFAULT '',
    uid                 CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE redis_instance;

CREATE TABLE IF NOT EXISTS rds_instance (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    label               CHAR(64) DEFAULT '',
    state               tinyint(1) NOT NULL DEFAULT 0 COMMENT '0. Unknown 1. Running 2. Recovering',
    domain              CHAR(64) DEFAULT '',
    region              CHAR(64) DEFAULT '',
    az                  CHAR(64) DEFAULT '',
    epc_id              INTEGER DEFAULT 0,
    type                INTEGER DEFAULT 0 COMMENT '0. Unknown 1. MySQL 2. SqlServer 3. PPAS 4. PostgreSQL 5. MariaDB',
    version             CHAR(64) DEFAULT '',
    series              tinyint(1) NOT NULL DEFAULT 0 COMMENT '0. Unknown 1. basic 2. HA',
    model               tinyint(1) NOT NULL DEFAULT 0 COMMENT '0. Unknown 1. Primary 2. Readonly 3. Temporary 4. Disaster recovery 5. share',
    uid                 CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE rds_instance;

CREATE TABLE IF NOT EXISTS lb (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    label               CHAR(64) DEFAULT '',
    model               INTEGER DEFAULT 0 COMMENT '1.Internal 2.External',
    vip                 CHAR(64) DEFAULT '',
    epc_id              INTEGER DEFAULT 0,
    az                  CHAR(64) DEFAULT '',
    region              CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    uid                 CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE lb;

CREATE TABLE IF NOT EXISTS lb_listener (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    lb_id               INTEGER DEFAULT 0,
    name                VARCHAR(256) DEFAULT '',
    ips                 TEXT COMMENT 'separated by ,',
    snat_ips            TEXT COMMENT 'separated by ,',
    label               CHAR(64) DEFAULT '',
    port                INTEGER DEFAULT NULL,
    protocol            CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE lb_listener;

CREATE TABLE IF NOT EXISTS lb_target_server (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    lb_id               INTEGER DEFAULT 0,
    lb_listener_id      INTEGER DEFAULT 0,
    epc_id              INTEGER DEFAULT 0,
    type                INTEGER DEFAULT 0 COMMENT '1.VM 2.IP',
    ip                  CHAR(64) DEFAULT '',
    vm_id               INTEGER DEFAULT 0,
    port                INTEGER DEFAULT NULL,
    protocol            CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT ''
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE lb_target_server;

CREATE TABLE IF NOT EXISTS lb_vm_connection (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    lb_id               INTEGER,
    vm_id               INTEGER,
    domain              CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT ''
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE lb_vm_connection;

CREATE TABLE IF NOT EXISTS vm_pod_node_connection (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    vm_id               INTEGER,
    pod_node_id         INTEGER,
    domain              CHAR(64) DEFAULT '',
    sub_domain          CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT ''
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE vm_pod_node_connection;

CREATE TABLE IF NOT EXISTS pod_cluster (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    cluster_name        VARCHAR(256) DEFAULT '',
    version             VARCHAR(256) DEFAULT '',
    epc_id              INTEGER,
    az                  CHAR(64) DEFAULT '',
    region              CHAR(64) DEFAULT '',
    sub_domain          CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE pod_cluster;

CREATE TABLE IF NOT EXISTS pod_node (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    alias               CHAR(64) DEFAULT '',
    type                INTEGER DEFAULT NULL COMMENT '1: Master 2: Node',
    server_type         INTEGER DEFAULT NULL COMMENT '1: Host 2: VM',
    state               INTEGER DEFAULT 1 COMMENT '0: Exception 1: Normal',
    ip                  CHAR(64) DEFAULT '',
    vcpu_num            INTEGER DEFAULT 0,
    mem_total           INTEGER DEFAULT 0 COMMENT 'unit: M',
    pod_cluster_id      INTEGER,
    region              CHAR(64) DEFAULT '',
    az                  CHAR(64) DEFAULT '',
    epc_id              INTEGER DEFAULT NULL,
    sub_domain          CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE pod_node;

CREATE TABLE IF NOT EXISTS pod (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    alias               CHAR(64) DEFAULT '',
    label               TEXT COMMENT 'separated by ,',
    state               INTEGER NOT NULL COMMENT '0.Exception 1.Running',
    pod_rs_id           INTEGER DEFAULT NULL,
    pod_group_id        INTEGER DEFAULT NULL,
    pod_namespace_id    INTEGER DEFAULT NULL,
    pod_node_id         INTEGER DEFAULT NULL,
    pod_cluster_id      INTEGER DEFAULT NULL,
    epc_id              INTEGER DEFAULT NULL,
    az                  CHAR(64) DEFAULT '',
    region              CHAR(64) DEFAULT '',
    sub_domain          CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE pod;

CREATE TABLE IF NOT EXISTS pod_rs (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    alias               CHAR(64) DEFAULT '',
    label               TEXT COMMENT 'separated by ,',
    pod_num             INTEGER DEFAULT 1,
    pod_group_id        INTEGER DEFAULT NULL,
    pod_namespace_id    INTEGER DEFAULT NULL,
    pod_cluster_id      INTEGER DEFAULT NULL,
    az                  CHAR(64) DEFAULT '',
    region              CHAR(64) DEFAULT '',
    sub_domain          CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE pod_rs;

CREATE TABLE IF NOT EXISTS pod_group (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    alias               CHAR(64) DEFAULT '',
    type                INTEGER DEFAULT NULL COMMENT '1: Deployment 2: StatefulSet 3: ReplicationController',
    pod_num             INTEGER DEFAULT 1,
    label               TEXT COMMENT 'separated by ,',
    pod_namespace_id    INTEGER DEFAULT NULL,
    pod_cluster_id      INTEGER DEFAULT NULL,
    az                  CHAR(64) DEFAULT '',
    region              CHAR(64) DEFAULT '',
    sub_domain          CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE pod_group;

CREATE TABLE IF NOT EXISTS pod_namespace (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    alias               CHAR(64) DEFAULT '',
    cloud_tags          TEXT COMMENT 'separated by ,',
    pod_cluster_id      INTEGER DEFAULT NULL,
    az                  CHAR(64) DEFAULT '',
    region              CHAR(64) DEFAULT '',
    sub_domain          CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE pod_namespace;

CREATE TABLE IF NOT EXISTS pod_service (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    alias               CHAR(64) DEFAULT '',
    type                INTEGER DEFAULT NULL COMMENT '1: ClusterIP 2: NodePort',
    selector            TEXT COMMENT 'separated by ,',
    service_cluster_ip  CHAR(64) DEFAULT '',
    pod_ingress_id      INTEGER DEFAULT NULL,
    pod_namespace_id    INTEGER DEFAULT NULL,
    pod_cluster_id      INTEGER DEFAULT NULL,
    epc_id              INTEGER DEFAULT NULL,
    az                  CHAR(64) DEFAULT '',
    region              CHAR(64) DEFAULT '',
    sub_domain          CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE pod_service;

CREATE TABLE IF NOT EXISTS pod_service_port (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    protocol            CHAR(64) DEFAULT '',
    port                INTEGER,
    target_port         INTEGER,
    node_port           INTEGER,
    pod_service_id      INTEGER DEFAULT NULL,
    sub_domain          CHAR(64) DEFAULT '',
    lcuuid              CHAR(64)
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE pod_service_port;

CREATE TABLE IF NOT EXISTS pod_group_port (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    protocol            CHAR(64) DEFAULT '',
    port                INTEGER,
    pod_group_id        INTEGER DEFAULT NULL,
    pod_service_id      INTEGER DEFAULT NULL,
    sub_domain          CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT ''
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE pod_group_port;

CREATE TABLE IF NOT EXISTS pod_ingress (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    alias               CHAR(64) DEFAULT '',
    pod_namespace_id    INTEGER DEFAULT NULL,
    pod_cluster_id      INTEGER DEFAULT NULL,
    az                  CHAR(64) DEFAULT '',
    region              CHAR(64) DEFAULT '',
    sub_domain          CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE pod_ingress;

CREATE TABLE IF NOT EXISTS pod_ingress_rule (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    protocol            CHAR(64) DEFAULT '',
    host                TEXT,
    pod_ingress_id      INTEGER DEFAULT NULL,
    sub_domain          CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT ''
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE pod_ingress_rule;

CREATE TABLE IF NOT EXISTS pod_ingress_rule_backend (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    path                TEXT,
    port                INTEGER,
    pod_service_id      INTEGER DEFAULT NULL,
    pod_ingress_rule_id INTEGER DEFAULT NULL,
    pod_ingress_id      INTEGER DEFAULT NULL,
    sub_domain          CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT ''
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE pod_ingress_rule_backend;

CREATE TABLE IF NOT EXISTS `contact` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(256) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '',
  `mobile` varchar(13) NOT NULL DEFAULT '',
  `email` varchar(128) NOT NULL DEFAULT '',
  `company` varchar(128) NOT NULL DEFAULT '',
  `push_email` TEXT COMMENT 'custom emails, separated by ;',
  `lcuuid` CHAR(64),
  `domain` CHAR(64),
  `deleted` TINYINT(1) DEFAULT 0,
  `create_method` tinyint(1) unsigned NOT NULL DEFAULT '0' COMMENT '0.created by UI 1.learning',
  `alarm_push` tinyint(1) unsigned NOT NULL DEFAULT '0' COMMENT '0.disabled 1.enabled',
  `report_push` tinyint(1) unsigned NOT NULL DEFAULT '0' COMMENT '0.disabled 1.enabled',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `report` (
  `id`                     INTEGER NOT NULL AUTO_INCREMENT,
  `title`                  varchar(200) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '' COMMENT 'Title of the report',
  `begin_at`               datetime DEFAULT NULL COMMENT 'Start time of the report',
  `end_at`                 datetime DEFAULT NULL COMMENT 'End time of the report',
  `policy_id`              int(10) unsigned NOT NULL DEFAULT '0' COMMENT 'report_policy ID',
  `content`                LONGTEXT,
  `lcuuid`                 varchar(64) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '',
  `created_at`             datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1 COMMENT='report records';

CREATE TABLE IF NOT EXISTS vtap (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                    VARCHAR(256) NOT NULL,
    state                   INTEGER DEFAULT 1 COMMENT '0.not-connected 1.normal',
    enable                  INTEGER DEFAULT 1 COMMENT '0: stop 1: running',
    type                    INTEGER DEFAULT 0 COMMENT '1: process 2: vm 3: public cloud 4: analyzer 5: physical machine 6: dedicated physical machine 7: host pod 8: vm pod',
    ctrl_ip                 CHAR(64) NOT NULL,
    ctrl_mac                CHAR(64),
    tap_mac                 CHAR(64),
    analyzer_ip             CHAR(64) NOT NULL,
    cur_analyzer_ip         CHAR(64) NOT NULL,
    controller_ip           CHAR(64) NOT NULL,
    cur_controller_ip       CHAR(64) NOT NULL,
    launch_server           CHAR(64) NOT NULL,
    launch_server_id        INTEGER,
    az                      CHAR(64) DEFAULT '',
    region                  CHAR(64) DEFAULT '',
    revision                VARCHAR(256),
    synced_controller_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    synced_analyzer_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    boot_time               INTEGER DEFAULT 0,
    exceptions              INTEGER UNSIGNED DEFAULT 0,
    vtap_lcuuid             CHAR(64) DEFAULT NULL,
    vtap_group_lcuuid       CHAR(64) DEFAULT NULL,
    cpu_num                 INTEGER DEFAULT 0 COMMENT 'logical number of cpu',
    memory_size             BIGINT DEFAULT 0,
    arch                    VARCHAR(256),
    os                      VARCHAR(256),
    kernel_version          VARCHAR(256),
    process_name            VARCHAR(256),
    license_type            INTEGER COMMENT '1: A类 2: B类 3: C类',
    license_functions       CHAR(64) COMMENT 'separated by ,; 1: 流量分发 2: 网络监控 3: 应用监控',
    tap_mode                INTEGER,
    expected_revision       TEXT,
    upgrade_package         TEXT,
    lcuuid                  CHAR(64)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE vtap;

CREATE TABLE IF NOT EXISTS vtap_group (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                    VARCHAR(64) NOT NULL,
    created_at              DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    lcuuid                  CHAR(64),
    short_uuid              CHAR(32)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE vtap_group;

CREATE TABLE IF NOT EXISTS topo_position (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    type                    INTEGER DEFAULT 1 COMMENT '3-link topo',
    user_id                 INTEGER NOT NULL,
    data                    TEXT,
    lcuuid                  CHAR(64)
) ENGINE=innodb DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=1;

CREATE TABLE IF NOT EXISTS acl (
    id                     INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    business_id            INTEGER NOT NULL,
    name                   CHAR(64),
    type                   INTEGER DEFAULT 2 COMMENT '1-epc; 2-custom',
    tap_type               INTEGER DEFAULT 3 COMMENT '1-WAN; 3-LAN',
    state                  INTEGER DEFAULT 1 COMMENT '0-disable; 1-enable',
    applications           CHAR(64) NOT NULL COMMENT 'separated by , (1-performance analysis; 2-backpacking; 6-npb)',
    epc_id                 INTEGER,
    src_group_ids          TEXT COMMENT 'separated by ,',
    dst_group_ids          TEXT COMMENT 'separated by ,',
    protocol               INTEGER,
    src_ports              TEXT COMMENT 'separated by ,',
    dst_ports              TEXT COMMENT 'separated by ,',
    vlan                   INTEGER,
    created_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             TIMESTAMP NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    lcuuid                 CHAR(64)
) ENGINE=innodb DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=1;
TRUNCATE TABLE acl;

CREATE TABLE IF NOT EXISTS `resource_group` (
  `id`                      INT(11) NOT NULL AUTO_INCREMENT,
  `business_id`             INTEGER NOT NULL,
  `lcuuid`                  VARCHAR(64) NOT NULL,
  `name`                    VARCHAR(200) NOT NULL DEFAULT '',
  `type`                    INTEGER NOT NULL COMMENT '3: anonymous vm, 4: anonymous ip, 5: anonymous pod, 6: anonymous pod_group, 8: anonymous pod_service, 81: anonymous pod_service as pod_group, 14: anonymous vl2',
  `ip_type`                 INTEGER COMMENT '1: single ip, 2: ip range, 3: cidr, 4.mix [1, 2, 3]',
  `ips`                     TEXT COMMENT 'ips separated by ,',
  `vm_ids`                  TEXT COMMENT 'vm ids separated by ,',
  `vl2_ids`                 TEXT COMMENT 'vl2 ids separated by ,',
  `epc_id`                  INTEGER,
  `pod_cluster_id`          INTEGER,
  `extra_info_ids`          TEXT COMMENT 'resource group extra info ids separated by ,',
  `lb_id`                   INTEGER,
  `lb_listener_id`          INTEGER,
  `icon_id`                 INTEGER DEFAULT -2,
  `created_at`              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

CREATE TABLE IF NOT EXISTS resource_group_extra_info (
    id                     INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    resource_type          INTEGER NOT NULL COMMENT '1: epc, 2: vm, 3: pod_service, 4: pod_group, 5: vl2, 6: pod_cluster, 7: pod',
    resource_id            INTEGER NOT NULL,
    resource_sub_type      INTEGER,
    pod_namespace_id       INTEGER,
    resource_name          VARCHAR(256) NOT NULL
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE resource_group_extra_info;

CREATE TABLE IF NOT EXISTS npb_policy (
    id                     INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                   CHAR(64),
    state                  INTEGER DEFAULT 1 COMMENT '0-disable; 1-enable',
    business_id            INTEGER NOT NULL,
    vni                    INTEGER,
    npb_tunnel_id          INTEGER,
    distribute             TINYINT(1) DEFAULT 1 COMMENT '0-drop, 1-distribute',
    payload_slice          INTEGER DEFAULT NULL,
    acl_id                 INTEGER,
    policy_acl_group_id    INTEGER,
    vtap_ids               TEXT COMMENT 'separated by ,',
    created_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             TIMESTAMP NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    lcuuid                 CHAR(64)
) ENGINE=innodb DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=1;
TRUNCATE TABLE npb_policy;

CREATE TABLE IF NOT EXISTS pcap_policy (
    id                     INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                   CHAR(64),
    state                  INTEGER DEFAULT 1 COMMENT '0-disable; 1-enable',
    business_id            INTEGER NOT NULL,
    acl_id                 INTEGER,
    vtap_ids               TEXT COMMENT 'separated by ,',
    payload_slice          INTEGER,
    policy_acl_group_id    INTEGER,
    user_id                INTEGER,
    created_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             TIMESTAMP NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    lcuuid                 CHAR(64)
) ENGINE=innodb DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=1;
TRUNCATE TABLE pcap_policy;

CREATE TABLE IF NOT EXISTS group_acl (
    id                     INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    group_id               INTEGER NOT NULL,
    acl_id                 INTEGER NOT NULL,
    lcuuid                 CHAR(64)
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE group_acl;

CREATE TABLE IF NOT EXISTS alarm_label (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    alarm_id                INTEGER NOT NULL,
    label_name              TEXT
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE alarm_label;

CREATE TABLE IF NOT EXISTS alarm_policy (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    sub_view_id             INTEGER,
    sub_view_type           TINYINT(1) DEFAULT 0,
    sub_view_name           TEXT,
    sub_view_url            TEXT,
    sub_view_params         TEXT,
    sub_view_metrics        TEXT,
    sub_view_extra          TEXT,
    user_id                 INTEGER,
    name                    CHAR(64) NOT NULL,
    level                   TINYINT(1) NOT NULL COMMENT '0.low 1.middle 2.high',
    state                   TINYINT(1) DEFAULT 1 COMMENT '0.disabled 1.enabled',
    app_type                TINYINT(1) NOT NULL COMMENT '1-system 2-360view',
    sub_type                TINYINT(1) DEFAULT 1 COMMENT '1-指标量;20-组件状态;21-组件性能;22-自动删除;23-资源状态;24-平台信息',
    deleted                 TINYINT(1) DEFAULT 0 COMMENT '0-not deleted; 1-deleted',
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at              DATETIME DEFAULT NULL,
    contrast_type           TINYINT(1) NOT NULL DEFAULT 1 COMMENT '1.abs 2.baseline',
    target_line_uid         TEXT,
    target_line_name        TEXT,
    target_field            TEXT,
    data_level              CHAR(64) NOT NULL DEFAULT "1m" COMMENT '1s or 1m',
    upper_threshold         DOUBLE,
    lower_threshold         DOUBLE,
    agg                     SMALLINT DEFAULT 0 COMMENT '0-聚合; 1-不聚合',
    delay                   SMALLINT DEFAULT 1 COMMENT '0-不延迟; 1-延迟',
    lcuuid                  CHAR(64)
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE alarm_policy;

CREATE TABLE IF NOT EXISTS label (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                    CHAR(64) NOT NULL,
    type                    INTEGER NOT NULL COMMENT '1-resource topo',
    host_id                 INTEGER,
    epc_ids                 TEXT COMMENT 'separated by ,',
    subnet_ids              TEXT COMMENT 'separated by ,',
    security_group_ids      TEXT COMMENT 'separated by ,',
    vm_ids                  TEXT COMMENT 'separated by ,',
    ips                     TEXT COMMENT 'separated by ,',
    lcuuid                  CHAR(64)
) ENGINE=innodb DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=1;
TRUNCATE TABLE label;

CREATE TABLE IF NOT EXISTS alarm_endpoint (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                    CHAR(64) NOT NULL,
    push_type               INTEGER NOT NULL COMMENT '0-email, 1-url, 2-pcap',
    description             TEXT,
    endpoints               TEXT COMMENT 'separated by ,',
    user_id                 INTEGER,
    start_type              INTEGER NOT NULL,
    end_type                INTEGER NOT NULL,
    method                  CHAR(64),
    header                  TEXT,
    body                    TEXT,
    lcuuid                  CHAR(64),
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=innodb DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=1;
TRUNCATE TABLE alarm_endpoint;

CREATE TABLE IF NOT EXISTS alarm_policy_endpoint_connection (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    alarm_id                INTEGER,
    endpoint_id             INTEGER
) ENGINE=innodb DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=1;
TRUNCATE TABLE alarm_policy_endpoint_connection;

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/alarm/vtap-lost/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"失联次数\", \"return_field_unit\": \"次\"}}]", "采集器失联",  1, 1, 1, 20, 1, "", "", "sysalarm_value", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/alarm/vtap-drop/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"队列丢包1分钟总量\", \"return_field_unit\": \"个\"}}]", "采集器丢包",  0, 1, 1, 21, 1, "", "", "sysalarm_value", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/alarm/tsdb-drop/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"队列丢包1分钟总量\", \"return_field_unit\": \"个\"}}]", "数据节点丢包",  0, 1, 1, 21, 1, "", "", "sysalarm_value", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/alarm/controller-load/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"系统负载与CPU总数的相对比例5分钟谷值\", \"return_field_unit\": \"%\"}}]", "控制器负载高",  0, 1, 1, 21, 1, "", "", "sysalarm_value", 70, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/alarm/analyzer-load/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"系统负载与CPU总数的相对比例5分钟谷值\", \"return_field_unit\": \"%\"}}]", "数据节点负载高",  0, 1, 1, 21, 1, "", "", "sysalarm_value", 70, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/alarm/vtap-exception/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"异常事件次数\", \"return_field_unit\": \"次\"}}]", "采集器异常",  1, 1, 1, 20, 1, "", "", "sysalarm_value", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/alarm/controller-lost/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"失联次数\", \"return_field_unit\": \"次\"}}]", "控制器失联",  2, 1, 1, 20, 1, "", "", "sysalarm_value", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/alarm/analyzer-lost/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"失联次数\", \"return_field_unit\": \"次\"}}]", "数据节点失联",  2, 1, 1, 20, 1, "", "", "sysalarm_value", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/alarm/controller-disk/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"磁盘使用空间比例\", \"return_field_unit\": \"%\"}}]", "控制器磁盘空间不足",  0, 1, 1, 21, 1, "", "", "sysalarm_value", 70, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/alarm/tsdb-disk/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"磁盘使用空间比例\", \"return_field_unit\": \"%\"}}]", "数据节点磁盘空间不足",  0, 1, 1, 21, 1, "", "", "sysalarm_value", 70, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/alarm/vtap-cpu/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"CPU消耗比例5分钟谷值\", \"return_field_unit\": \"%\"}}]", "采集器CPU超限",  0, 1, 1, 21, 1, "", "", "sysalarm_value", 70, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/alarm/vtap-memory/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"内存消耗比例5分钟谷值\", \"return_field_unit\": \"%\"}}]", "采集器内存超限",  0, 1, 1, 21, 1, "", "", "sysalarm_value", 70, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/alarm/tsdb-write-failed/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"数据节点写入失败次数\", \"return_field_unit\": \"次\"}}]", "数据节点写入失败",  1, 1, 1, 21, 1, "", "", "sysalarm_value", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field, agg,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/alarm/process-start/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"进程启动次数\", \"return_field_unit\": \"次\"}}]", "进程启动",  0, 1, 1, 20, 1, "", "", "sysalarm_value", 1, 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field, agg,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/alarm/process-end/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"进程停止次数\", \"return_field_unit\": \"次\"}}]", "进程停止",  0, 1, 1, 20, 1, "", "", "sysalarm_value", 1, 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field, agg,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/alarm/policy-event/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"策略自动删除触发次数\", \"return_field_unit\": \"次\"}}]", "策略自动删除",  0, 1, 1, 22, 1, "", "", "sysalarm_value", 1, 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/alarm/platform-event/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"云平台同步异常触发次数\", \"return_field_unit\": \"次\"}}]", "云平台同步异常",  1, 1, 1, 23, 1, "", "", "sysalarm_value", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field, data_level, agg, delay,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/alarm/voucher-30days/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"可用天数\", \"return_field_unit\": \"天\"}}]", "DeepFlow预估可用天数不足30天",  1, 1, 1, 24, 1, "", "", "sysalarm_value", "1d", 1, 0, NULL, 30, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field, data_level, agg, delay,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/alarm/voucher-0days/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"可用天数\", \"return_field_unit\": \"天\"}}]", "DeepFlow停止服务",  2, 1, 1, 24, 1, "", "", "sysalarm_value", "1d", 1, 0, NULL, 0, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field, data_level, agg, delay,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/alarm/license-30days/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"最近一个要到期的授权文件\", \"return_field_unit\": \"天\"}}]", "DeepFlow授权不足30天",  1, 1, 1, 24, 1, "", "", "sysalarm_value", "1d", 1, 0, NULL, 30, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field, data_level, agg, delay,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/alarm/license-0days/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"最近一个要到期的授权文件\", \"return_field_unit\": \"天\"}}]", "DeepFlow授权过期",  2, 1, 1, 24, 1, "", "", "sysalarm_value", "1d", 1, 0, NULL, 0, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/alarm/vtap-sys-free-memory/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"系统空闲内存比例与空闲内存限制的比例5分钟内最大值\", \"return_field_unit\": \"%\"}}]", "采集器系统空闲内存比例超限",  0, 1, 1, 21, 1, "", "", "sysalarm_value", NULL, 150, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/alarm/vtap-logcount-warning/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"WARN日志条数1分钟总量\", \"return_field_unit\": \"条\"}}]", "采集器的WARN日志条数超限",  0, 1, 1, 20, 1, "", "", "sysalarm_value", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/alarm/vtap-logcount-error/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"ERR日志条数1分钟总量\", \"return_field_unit\": \"条\"}}]", "采集器的ERR日志条数超限",  1, 1, 1, 20, 1, "", "", "sysalarm_value", 1, NULL, @lcuuid);

set @lcuuid = (select uuid());
INSERT INTO alarm_policy(sub_view_type, sub_view_url, sub_view_params, sub_view_metrics, name, level, state,
    app_type, sub_type, contrast_type, target_line_uid, target_line_name, target_field,
    upper_threshold, lower_threshold, lcuuid)
    values(1, "/v1/alarm/sync-k8sinfo-delay/", "{}", "[{\"OPERATOR\": {\"return_field\": \"sysalarm_value\", \"return_field_description\": \"同步滞后时间\", \"return_field_unit\": \"秒\"}}]", "K8s容器信息同步滞后",  1, 1, 1, 23, 1, "", "", "sysalarm_value", 600, NULL, @lcuuid);

CREATE TABLE IF NOT EXISTS report_policy (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                    CHAR(64) NOT NULL,
    view_id                 INTEGER NOT NULL,
    user_id                 INTEGER,
    `data_level`            enum('1s','1m') NOT NULL DEFAULT '1m',
    report_format           TINYINT(1) DEFAULT 1 COMMENT 'Type of format (1-html)',
    report_type             TINYINT(1) DEFAULT 1 COMMENT 'Type of reports (0-daily; 1-weekly; 2-monthly)',
    `interval`              enum('1d','1h') NOT NULL DEFAULT '1h',
    state                   TINYINT(1) DEFAULT 1 COMMENT '0-disable; 1-enable',
    push_type               TINYINT(1) DEFAULT 1 COMMENT '1-email',
    push_email              TEXT COMMENT 'separated by ,',
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    begin_at                TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lcuuid                  CHAR(64) NOT NULL
) ENGINE=innodb DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=1;
TRUNCATE TABLE report_policy;

CREATE TABLE IF NOT EXISTS policy_acl_group (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    acl_ids                 TEXT NOT NULL COMMENT 'separated by ,',
    `count`                 INTEGER NOT NULL
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE policy_acl_group;

CREATE TABLE IF NOT EXISTS vtap_group_configuration(
    id                        INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    max_collect_pps           INTEGER DEFAULT NULL,
    max_npb_bps               BIGINT DEFAULT NULL COMMENT 'unit: bps',
    max_cpus                  INTEGER DEFAULT NULL,
    max_memory                INTEGER DEFAULT NULL COMMENT 'unit: M',
    sync_interval             INTEGER DEFAULT NULL,
    stats_interval            INTEGER,
    rsyslog_enabled           TINYINT(1) COMMENT '0: disabled 1:enabled',
    max_tx_bandwidth          BIGINT COMMENT 'unit: bps',
    bandwidth_probe_interval  INTEGER,
    tap_interface_regex       TEXT,
    max_escape_seconds        INTEGER,
    mtu                       INTEGER,
    output_vlan               INTEGER DEFAULT NULL,
    collector_socket_type     CHAR(64),
    compressor_socket_type    CHAR(64),
    npb_socket_type           CHAR(64),
    npb_vlan_mode             INTEGER,
    collector_enabled         TINYINT(1) COMMENT '0: disabled 1:enabled',
    vtap_flow_1s_enabled      TINYINT(1) COMMENT '0: disabled 1:enabled',
    l4_log_tap_types          TEXT COMMENT 'tap type info, separate by ","',
    npb_dedup_enabled         TINYINT(1) COMMENT '0: disabled 1:enabled',
    platform_enabled          TINYINT(1) COMMENT '0: disabled 1:enabled',
    if_mac_source             INTEGER COMMENT '0: 接口MAC 1: 接口名称 2: 虚拟机MAC解析',
    vm_xml_path               TEXT,
    extra_netns_regex         TEXT,
    nat_ip_enabled            TINYINT(1) COMMENT '0: disabled 1:enabled',
    capture_packet_size       INTEGER,
    inactive_server_port_enabled   TINYINT(1) COMMENT '0: disabled 1:enabled',
    inactive_ip_enabled       TINYINT(1) COMMENT '0: disabled 1:enabled',
    vtap_group_lcuuid         CHAR(64) DEFAULT NULL,
    log_threshold             INTEGER,
    log_level                 CHAR(64),
    log_retention             INTEGER,
    http_log_proxy_client     CHAR(64),
    http_log_trace_id         CHAR(64),
    l7_log_packet_size        INTEGER,
    l4_log_collect_nps_threshold   INTEGER,
    l7_log_collect_nps_threshold   INTEGER,
    l7_metrics_enabled        TINYINT(1) COMMENT '0: disabled 1:enabled',
    l7_log_store_tap_types    TEXT COMMENT 'l7 log store tap types, separate by ","',
    decap_type                TEXT COMMENT 'separate by ","',
    capture_socket_type       INTEGER,
    capture_bpf               VARCHAR(512),
    tap_mode                  INTEGER COMMENT '0: local 1: virtual mirror 2: physical mirror',
    thread_threshold          INTEGER,
    process_threshold         INTEGER,
    ntp_enabled               TINYINT(1) COMMENT '0: disabled 1:enabled',
    l4_performance_enabled    TINYINT(1) COMMENT '0: disabled 1:enabled',
    pod_cluster_internal_ip   TINYINT(1) COMMENT '0: 所有集群 1:采集器所在集群',
    domains                   TEXT COMMENT 'domains info, separate by ","',
    http_log_span_id          CHAR(64),
    http_log_x_request_id     CHAR(64),
    sys_free_memory_limit     INTEGER DEFAULT NULL COMMENT 'unit: %',
    log_file_size             INTEGER DEFAULT NULL COMMENT 'unit: MB',
    external_agent_http_proxy_enabled  TINYINT(1) COMMENT '0: disabled 1:enabled',
    external_agent_http_proxy_port     INTEGER DEFAULT NULL,
    proxy_controller_port     INTEGER DEFAULT NULL,
    analyzer_port             INTEGER DEFAULT NULL,
    proxy_controller_ip       VARCHAR(128),
    analyzer_ip               VARCHAR(128),
    yaml_config               TEXT,
    lcuuid                    CHAR(64)
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE vtap_group_configuration;

CREATE TABLE IF NOT EXISTS npb_tunnel (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                CHAR(64) NOT NULL,
    ip                  CHAR(64),
    type                INTEGER COMMENT '(0-VXLAN；1-ERSPAN)',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    lcuuid              CHAR(64)
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE npb_tunnel;

CREATE TABLE IF NOT EXISTS tap_type (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                CHAR(64) NOT NULL,
    type                INTEGER NOT NULL DEFAULT 1 COMMENT '1:packet, 2:sFlow, 3:NetFlow V5 4:NetStream v5',
    region              CHAR(64),
    value               INTEGER NOT NULL,
    vlan                INTEGER,
    src_ip              CHAR(64),
    interface_index     INTEGER UNSIGNED COMMENT '1 ~ 2^32-1',
    interface_name      CHAR(64),
    sampling_rate       INTEGER UNSIGNED COMMENT '1 ~ 2^32-1',
    description         VARCHAR(256),
    lcuuid              CHAR(64)
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE tap_type;

set @lcuuid = (select uuid());
INSERT INTO tap_type(name, value, vlan, description, lcuuid) values('虚拟网络', 3, 768, '', @lcuuid);

CREATE TABLE IF NOT EXISTS genesis_host (
    id          INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    hostname    VARCHAR(256),
    ip          CHAR(64)
) ENGINE=innodb DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1;
TRUNCATE TABLE genesis_host;

CREATE TABLE IF NOT EXISTS genesis_vm (
    id              INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    uuid            CHAR(64),
    name            VARCHAR(256),
    label           CHAR(64),
    vpc_uuid        CHAR(64),
    launch_server   CHAR(64),
    state           INTEGER
) ENGINE=innodb DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1;
TRUNCATE TABLE genesis_vm;

CREATE TABLE IF NOT EXISTS genesis_vpc (
    id              INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    uuid            CHAR(64),
    name            VARCHAR(256)
) ENGINE=innodb DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1;
TRUNCATE TABLE genesis_vpc;

CREATE TABLE IF NOT EXISTS genesis_network (
    id              INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name            VARCHAR(256),
    uuid            CHAR(64),
    segmentation_id INTEGER,
    net_type        INTEGER,
    external        TINYINT(1),
    vpc_uuid        CHAR(64)
) ENGINE=innodb DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1;
TRUNCATE TABLE genesis_network;

CREATE TABLE IF NOT EXISTS genesis_port (
    id              INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    uuid            CHAR(64),
    type            INTEGER,
    mac_address     CHAR(32),
    device_uuid     CHAR(64),
    network_uuid    CHAR(64),
    vpc_uuid        CHAR(64)
) ENGINE=innodb DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1;
TRUNCATE TABLE genesis_port;

CREATE TABLE IF NOT EXISTS genesis_ip (
    id              INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    uuid            CHAR(64),
    ip              CHAR(64),
    port_uuid       CHAR(64),
    last_seen       INTEGER,
    masklen         INTEGER DEFAULT 0
) ENGINE=innodb DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1;
TRUNCATE TABLE genesis_ip;

CREATE TABLE IF NOT EXISTS genesis_lldp (
    id                 INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    uuid               CHAR(64),
    host_ip            CHAR(48),
    host_interface     CHAR(64),
    system_name        VARCHAR(512),
    management_address VARCHAR(512),
    port_id            VARCHAR(512),
    port_description   VARCHAR(512),
    last_seen          INTEGER
) ENGINE=innodb DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1;
TRUNCATE TABLE genesis_lldp;

CREATE TABLE IF NOT EXISTS genesis_vinterface (
    id                    INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    uuid                  CHAR(64),
    name                  CHAR(64),
    mac                   CHAR(32),
    ips                   TEXT,
    tap_name              CHAR(64),
    tap_mac               CHAR(32),
    device_uuid           CHAR(64),
    device_name           VARCHAR(512),
    device_type           CHAR(64),
    host_ip               CHAR(48),
    last_seen             INTEGER,
    vtap_id               INTEGER,
    kubernetes_cluster_id CHAR(64)
) ENGINE=innodb DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1;
TRUNCATE TABLE genesis_vinterface;

CREATE TABLE IF NOT EXISTS go_genesis_host (
    id          INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    lcuuid      CHAR(64),
    hostname    VARCHAR(256),
    ip          CHAR(64),
    vtap_id     INTEGER,
    node_ip     CHAR(48)
) ENGINE=innodb DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1;
TRUNCATE TABLE go_genesis_host;

CREATE TABLE IF NOT EXISTS go_genesis_vm (
    id              INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    lcuuid          CHAR(64),
    name            VARCHAR(256),
    label           CHAR(64),
    vpc_lcuuid      CHAR(64),
    launch_server   CHAR(64),
    node_ip         CHAR(48),
    state           INTEGER,
    vtap_id         INTEGER,
    created_at      DATETIME
) ENGINE=innodb DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1;
TRUNCATE TABLE go_genesis_vm;

CREATE TABLE IF NOT EXISTS go_genesis_vpc (
    id              INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    lcuuid          CHAR(64),
    node_ip         CHAR(48),
    vtap_id         INTEGER,
    name            VARCHAR(256)
) ENGINE=innodb DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1;
TRUNCATE TABLE go_genesis_vpc;

CREATE TABLE IF NOT EXISTS go_genesis_network (
    id              INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name            VARCHAR(256),
    lcuuid          CHAR(64),
    segmentation_id INTEGER,
    net_type        INTEGER,
    external        TINYINT(1),
    vpc_lcuuid      CHAR(64),
    vtap_id         INTEGER,
    node_ip         CHAR(48)
) ENGINE=innodb DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1;
TRUNCATE TABLE go_genesis_network;

CREATE TABLE IF NOT EXISTS go_genesis_port (
    id              INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    lcuuid          CHAR(64),
    type            INTEGER,
    device_type     INTEGER,
    mac             CHAR(32),
    device_lcuuid   CHAR(64),
    network_lcuuid  CHAR(64),
    vpc_lcuuid      CHAR(64),
    vtap_id         INTEGER,
    node_ip         CHAR(48)
) ENGINE=innodb DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1;
TRUNCATE TABLE go_genesis_port;

CREATE TABLE IF NOT EXISTS go_genesis_ip (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    lcuuid              CHAR(64),
    ip                  CHAR(64),
    vinterface_lcuuid   CHAR(64),
    node_ip             CHAR(48),
    last_seen           DATETIME,
    vtap_id             INTEGER,
    masklen             INTEGER DEFAULT 0
) ENGINE=innodb DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1;
TRUNCATE TABLE go_genesis_ip;

CREATE TABLE IF NOT EXISTS go_genesis_lldp (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    lcuuid                  CHAR(64),
    host_ip                 CHAR(48),
    host_interface          CHAR(64),
    node_ip                 CHAR(48),
    system_name             VARCHAR(512),
    management_address      VARCHAR(512),
    vinterface_lcuuid       VARCHAR(512),
    vinterface_description  VARCHAR(512),
    vtap_id                 INTEGER,
    last_seen               DATETIME
) ENGINE=innodb DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1;
TRUNCATE TABLE go_genesis_lldp;

CREATE TABLE IF NOT EXISTS go_genesis_vinterface (
    id                    INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    lcuuid                CHAR(64),
    name                  CHAR(64),
    mac                   CHAR(32),
    ips                   TEXT,
    tap_name              CHAR(64),
    tap_mac               CHAR(32),
    device_lcuuid         CHAR(64),
    device_name           VARCHAR(512),
    device_type           CHAR(64),
    host_ip               CHAR(48),
    node_ip               CHAR(48),
    last_seen             DATETIME,
    vtap_id               INTEGER,
    kubernetes_cluster_id CHAR(64)
) ENGINE=innodb DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1;
TRUNCATE TABLE go_genesis_vinterface;

CREATE TABLE IF NOT EXISTS go_genesis_process (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    vtap_id             INTEGER NOT NULL DEFAULT 0,
    pid                 INTEGER NOT NULL,
    lcuuid              CHAR(64) DEFAULT '',
    name                VARCHAR(256) DEFAULT '',
    process_name        VARCHAR(256) DEFAULT '',
    cmd_line            TEXT,
    user                VARCHAR(256) DEFAULT '',
    os_app_tags         TEXT COMMENT 'separated by ,',
    node_ip             CHAR(48) DEFAULT '',
    start_time          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE go_genesis_process;

CREATE TABLE IF NOT EXISTS go_genesis_storage (
    id          INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    vtap_id     INTEGER,
    node_ip     CHAR(48)
) ENGINE = innodb DEFAULT CHARSET = utf8mb4 AUTO_INCREMENT = 1;
TRUNCATE TABLE go_genesis_storage;

CREATE TABLE IF NOT EXISTS controller (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    state               INTEGER COMMENT '0.Temp 1.Creating 2.Complete 3.Modifying 4.Exception',
    name                CHAR(64),
    description         VARCHAR(256),
    ip                  CHAR(64),
    nat_ip              CHAR(64),
    cpu_num             INTEGER DEFAULT 0 COMMENT 'logical number of cpu',
    memory_size         BIGINT DEFAULT 0,
    arch                VARCHAR(256),
    os                  VARCHAR(256),
    kernel_version      VARCHAR(256),
    vtap_max            INTEGER DEFAULT 2000,
    synced_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    nat_ip_enabled      TINYINT(1) DEFAULT 0 COMMENT '0: disabled 1:enabled',
    node_type           INTEGER DEFAULT 2 COMMENT 'region node type 1.master 2.slave',
    region_domain_prefix VARCHAR(256) DEFAULT '',
    node_name           CHAR(64),
    pod_ip              CHAR(64),
    pod_name            CHAR(64),
    ca_md5              CHAR(64),
    lcuuid              CHAR(64)
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE controller;

CREATE TABLE IF NOT EXISTS analyzer (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    state                   INTEGER COMMENT '0.Temp 1.Creating 2.Complete 3.Modifying 4.Exception',
    ha_state                INTEGER DEFAULT 1 COMMENT '1.master 2.backup',
    name                    CHAR(64),
    description             VARCHAR(256),
    ip                      CHAR(64),
    nat_ip                  CHAR(64),
    agg                     INTEGER DEFAULT 1,
    cpu_num                 INTEGER DEFAULT 0 COMMENT 'logical number of cpu',
    memory_size             BIGINT DEFAULT 0,
    arch                    VARCHAR(256),
    os                      VARCHAR(256),
    kernel_version          VARCHAR(256),
    tsdb_shard_id           INTEGER,
    tsdb_replica_ip         CHAR(64),
    tsdb_data_mount_path    VARCHAR(256),
    pcap_data_mount_path    VARCHAR(256),
    vtap_max                INTEGER DEFAULT 200,
    synced_at               DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    nat_ip_enabled          TINYINT(1) DEFAULT 0 COMMENT '0: disabled 1:enabled',
    pod_ip                  CHAR(64),
    pod_name                CHAR(64),
    ca_md5                  CHAR(64),
    lcuuid                  CHAR(64)
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE analyzer;

CREATE TABLE IF NOT EXISTS link (
    id                      INTEGER NOT NULL auto_increment PRIMARY KEY,
    name                    CHAR(64),
    src_net_ele_id          INTEGER COMMENT 'network element id',
    dst_net_ele_id          INTEGER COMMENT 'network element id',
    src_tap_type            INTEGER,
    dst_tap_type            INTEGER,
    created_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    lcuuid                  CHAR(64)
)engine=innodb AUTO_INCREMENT=1  DEFAULT CHARSET=utf8;
TRUNCATE TABLE link;

CREATE TABLE IF NOT EXISTS network_element (
    id                    INTEGER NOT NULL auto_increment PRIMARY KEY,
    name                  CHAR(64),
    alias                 CHAR(64),
    type                  INTEGER DEFAULT 1 COMMENT '1. Switch, 2. Firewall, 3. Router, 4. GateWay, 5. Internet, 6. Domain, 7.SpecialLine, 8.Other',
    region                CHAR(64),
    create_method         INTEGER NOT NULL DEFAULT '0' COMMENT '0.user define 1.learning',
    created_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    lcuuid                CHAR(64)
)engine=innodb AUTO_INCREMENT=1  DEFAULT CHARSET=utf8;
TRUNCATE TABLE network_element;

CREATE TABLE IF NOT EXISTS ch_region (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    icon_id                 INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_region;

CREATE TABLE IF NOT EXISTS ch_az (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    icon_id                 INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_az;

CREATE TABLE IF NOT EXISTS ch_l3_epc (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    uid                     CHAR(64),
    icon_id                 INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_l3_epc;

CREATE TABLE IF NOT EXISTS ch_subnet (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    icon_id                 INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_subnet;

CREATE TABLE IF NOT EXISTS ch_pod_cluster (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    icon_id                 INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_pod_cluster;

CREATE TABLE IF NOT EXISTS ch_pod_node (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    icon_id                 INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_pod_node;

CREATE TABLE IF NOT EXISTS ch_pod_ns (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    icon_id                 INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_pod_ns;

CREATE TABLE IF NOT EXISTS ch_pod_group (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    icon_id                 INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_pod_group;

CREATE TABLE IF NOT EXISTS ch_pod (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    icon_id                 INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_pod;

CREATE TABLE IF NOT EXISTS ch_device (
    devicetype              INTEGER NOT NULL,
    deviceid                INTEGER NOT NULL,
    name                    VARCHAR(256),
    uid                     CHAR(64),
    icon_id                 INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (devicetype, deviceid)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_device;

CREATE TABLE IF NOT EXISTS ch_vtap_port (
    vtap_id                 INTEGER NOT NULL,
    tap_port                BIGINT NOT NULL,
    name                    VARCHAR(256),
    mac_type                INTEGER DEFAULT 1 COMMENT '1:tap_mac,2:mac',
    host_id                 INTEGER,
    host_name               VARCHAR(256),
    device_type             INTEGER,
    device_id               INTEGER,
    device_name             VARCHAR(256),
    icon_id                 INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (vtap_id, tap_port)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_vtap_port;

CREATE TABLE IF NOT EXISTS ch_tap_type (
    value                   INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256) NOT NULL,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_tap_type;

CREATE TABLE IF NOT EXISTS ch_vtap (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    type                    INTEGER,
    icon_id                 INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_vtap;

CREATE TABLE IF NOT EXISTS ch_k8s_label (
    `pod_id`        INTEGER NOT NULL,
    `key`           VARCHAR(256) NOT NULL,
    `value`         VARCHAR(256),
    `l3_epc_id`     INTEGER,
    `pod_ns_id`     INTEGER,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`pod_id`, `key`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_k8s_label;

CREATE TABLE IF NOT EXISTS ch_k8s_labels (
    `pod_id`        INTEGER NOT NULL PRIMARY KEY,
    `labels`        TEXT,
    `l3_epc_id`     INTEGER,
    `pod_ns_id`     INTEGER,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_k8s_labels;

CREATE TABLE IF NOT EXISTS ch_pod_node_port (
    id                      INTEGER NOT NULL,
    protocol                INTEGER NOT NULL,
    port                    INTEGER NOT NULL,
    port_lb_id              INTEGER,
    port_lb_name            VARCHAR(256),
    port_lb_listener_id     INTEGER,
    port_lb_listener_name   VARCHAR(256),
    port_pod_service_id     INTEGER,
    port_pod_service_name   VARCHAR(256),
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id, protocol, port)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_pod_node_port;

CREATE TABLE IF NOT EXISTS ch_pod_group_port (
    id                      INTEGER NOT NULL,
    protocol                INTEGER NOT NULL,
    port                    INTEGER NOT NULL,
    port_lb_id              INTEGER,
    port_lb_name            VARCHAR(256),
    port_lb_listener_id     INTEGER,
    port_lb_listener_name   VARCHAR(256),
    port_pod_service_id     INTEGER,
    port_pod_service_name   VARCHAR(256),
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id, protocol, port)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_pod_group_port;

CREATE TABLE IF NOT EXISTS ch_pod_port (
    id                      INTEGER NOT NULL,
    protocol                INTEGER NOT NULL,
    port                    INTEGER NOT NULL,
    port_lb_id              INTEGER,
    port_lb_name            VARCHAR(256),
    port_lb_listener_id     INTEGER,
    port_lb_listener_name   VARCHAR(256),
    port_pod_service_id     INTEGER,
    port_pod_service_name   VARCHAR(256),
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id, protocol, port)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_pod_port;

CREATE TABLE IF NOT EXISTS ch_device_port (
    devicetype              INTEGER NOT NULL,
    deviceid                INTEGER NOT NULL,
    protocol                INTEGER NOT NULL,
    port                    INTEGER NOT NULL,
    port_lb_id              INTEGER,
    port_lb_name            VARCHAR(256),
    port_lb_listener_id     INTEGER,
    port_lb_listener_name   VARCHAR(256),
    port_pod_service_id     INTEGER,
    port_pod_service_name   VARCHAR(256),
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (devicetype, deviceid, protocol, port)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_device_port;

CREATE TABLE IF NOT EXISTS ch_ip_port (
    ip                      VARCHAR(64) NOT NULL,
    subnet_id               INTEGER NOT NULL,
    protocol                INTEGER NOT NULL,
    port                    INTEGER NOT NULL,
    port_lb_id              INTEGER,
    port_lb_name            VARCHAR(256),
    port_lb_listener_id     INTEGER,
    port_lb_listener_name   VARCHAR(256),
    port_pod_service_id     INTEGER,
    port_pod_service_name   VARCHAR(256),
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (ip, subnet_id, protocol, port)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_ip_port;

CREATE TABLE IF NOT EXISTS ch_server_port (
    server_port             INTEGER NOT NULL PRIMARY KEY,
    server_port_name        VARCHAR(256),
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_server_port;

CREATE TABLE IF NOT EXISTS ch_ip_relation (
    l3_epc_id           INTEGER NOT NULL,
    ip                  CHAR(64) NOT NULL,
    natgw_id            INTEGER,
    natgw_name          VARCHAR(256),
    lb_id               INTEGER,
    lb_name             VARCHAR(256),
    lb_listener_id      INTEGER,
    lb_listener_name    VARCHAR(256),
    pod_ingress_id      INTEGER,
    pod_ingress_name    VARCHAR(256),
    pod_service_id      INTEGER,
    pod_service_name    VARCHAR(256),
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (l3_epc_id, ip)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_ip_relation;

CREATE TABLE IF NOT EXISTS ch_ip_resource (
    ip                  VARCHAR(64) NOT NULL,
    subnet_id           INTEGER NOT NULL,
    subnet_name         VARCHAR(256),
    region_id           INTEGER,
    region_name         VARCHAR(256),
    az_id               INTEGER,
    az_name             VARCHAR(256),
    host_id             INTEGER,
    host_name           VARCHAR(256),
    chost_id            INTEGER,
    chost_name          VARCHAR(256),
    vpc_id              INTEGER,
    vpc_name            VARCHAR(256),
    router_id           INTEGER,
    router_name         VARCHAR(256),
    dhcpgw_id           INTEGER,
    dhcpgw_name         VARCHAR(256),
    lb_id               INTEGER,
    lb_name             VARCHAR(256),
    lb_listener_id      INTEGER,
    lb_listener_name    VARCHAR(256),
    natgw_id            INTEGER,
    natgw_name          VARCHAR(256),
    redis_id            INTEGER,
    redis_name          VARCHAR(256),
    rds_id              INTEGER,
    rds_name            VARCHAR(256),
    pod_cluster_id      INTEGER,
    pod_cluster_name    VARCHAR(256),
    pod_ns_id           INTEGER,
    pod_ns_name         VARCHAR(256),
    pod_node_id         INTEGER,
    pod_node_name       VARCHAR(256),
    pod_ingress_id      INTEGER,
    pod_ingress_name    VARCHAR(256),
    pod_service_id      INTEGER,
    pod_service_name    VARCHAR(256),
    pod_group_id        INTEGER,
    pod_group_name      VARCHAR(256),
    pod_id              INTEGER,
    pod_name            VARCHAR(256),
    uid                 CHAR(64),
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (ip, subnet_id)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_ip_resource;

CREATE TABLE IF NOT EXISTS ch_lb_listener (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_lb_listener;

CREATE TABLE IF NOT EXISTS ch_pod_ingress (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_pod_ingress;

CREATE TABLE IF NOT EXISTS ch_node_type (
    resource_type           INTEGER NOT NULL DEFAULT 0 PRIMARY KEY,
    node_type               VARCHAR(256),
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_node_type;

INSERT INTO vl2(state, name, net_type, isp, lcuuid, domain) values(0, 'PublicNetwork', 3, 7, 'ffffffff-ffff-ffff-ffff-ffffffffffff', 'ffffffff-ffff-ffff-ffff-ffffffffffff');

set @lcuuid = (select uuid());
set @short_uuid = (select substr(replace(uuid(),'-',''), 1, 10));
set @short_uuid = concat('g-', @short_uuid);
INSERT INTO vtap_group(lcuuid, id, name, short_uuid) values(@lcuuid, 1, "default", @short_uuid);

CREATE TABLE IF NOT EXISTS data_source (
    id                          INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                        CHAR(64),
    tsdb_type                   CHAR(64),
    state                       INTEGER DEFAULT 1 COMMENT '0: Exception 1: Normal',
    base_data_source_id         INTEGER,
    `interval`                  INTEGER NOT NULL COMMENT 'uint: s',
    retention_time              INTEGER NOT NULL COMMENT 'uint: day',
    summable_metrics_operator   CHAR(64),
    unsummable_metrics_operator CHAR(64),
    updated_at              DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    lcuuid                  CHAR(64)
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE data_source;

set @lcuuid = (select uuid());
INSERT INTO data_source (id, name, tsdb_type, `interval`, retention_time, lcuuid) VALUES (1, '1s', 'flow', 1, 1, @lcuuid);
set @lcuuid = (select uuid());
INSERT INTO data_source (id, name, tsdb_type, base_data_source_id, `interval`, retention_time, summable_metrics_operator, unsummable_metrics_operator, lcuuid) VALUES (3, '1m', 'flow', 1, 60, 7, 'Sum', 'Avg', @lcuuid);
set @lcuuid = (select uuid());
INSERT INTO data_source (id, name, tsdb_type, `interval`, retention_time, lcuuid) VALUES (6, 'flow_log.l4', 'flow_log.l4', 0, 3, @lcuuid);
set @lcuuid = (select uuid());
INSERT INTO data_source (id, name, tsdb_type, `interval`, retention_time, lcuuid) VALUES (7, '1s', 'app', 1, 1, @lcuuid);
set @lcuuid = (select uuid());
INSERT INTO data_source (id, name, tsdb_type, base_data_source_id, `interval`, retention_time, summable_metrics_operator, unsummable_metrics_operator, lcuuid) VALUES (8, '1m', 'app', 7, 60, 7, 'Sum', 'Avg', @lcuuid);
set @lcuuid = (select uuid());
INSERT INTO data_source (id, name, tsdb_type, `interval`, retention_time, lcuuid) VALUES (9, 'flow_log.l7', 'flow_log.l7', 0, 3, @lcuuid);

CREATE TABLE IF NOT EXISTS license (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    status              INTEGER DEFAULT 0,
    name                VARCHAR(256),
    value               blob,
    lcuuid              CHAR(64)
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE license;

CREATE TABLE IF NOT EXISTS sys_event_alarm (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    process_name        VARCHAR(256),
    event_content       TEXT,
    event_type          INTEGER COMMENT '1.policy 2.vtap',
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    state               INTEGER COMMENT '0.wait 1.alarmed',
    extra_info          TEXT,
    lcuuid              CHAR(64)
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE sys_event_alarm;

CREATE TABLE IF NOT EXISTS voucher (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    status              INTEGER DEFAULT 0,
    name                VARCHAR(256) DEFAULT NULL,
    value               blob,
    lcuuid              CHAR(64) DEFAULT NULL
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE voucher;

CREATE TABLE IF NOT EXISTS consumer_bill (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    vtap_name               VARCHAR(256) DEFAULT NULL,
    vtap_ctrl_ip            CHAR(64) DEFAULT NULL,
    vtap_ctrl_mac           CHAR(64) DEFAULT NULL,
    monitor_type            INTEGER DEFAULT NULL,
    transaction_time        datetime(6) DEFAULT NULL,
    consumption_price       float(10,2) DEFAULT NULL,
    consumption_service     INTEGER DEFAULT NULL,
    consumption_period      VARCHAR(256) DEFAULT NULL,
    remaining_sum           double(10,2) DEFAULT NULL,
    voucher_lcuuid          CHAR(64) DEFAULT NULL,
    voucher_name            CHAR(64) DEFAULT NULL,
    billing_mode            INTEGER DEFAULT NULL,
    lcuuid                  CHAR(64) DEFAULT NULL
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE consumer_bill;

CREATE TABLE IF NOT EXISTS kubernetes_cluster (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    cluster_id              VARCHAR(256) NOT NULL ,
    value                   VARCHAR(256) NOT NULL,
    created_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    synced_at               DATETIME DEFAULT NULL,
    unique (cluster_id)
)ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE kubernetes_cluster;

CREATE TABLE IF NOT EXISTS ch_string_enum (
    tag_name                VARCHAR(256) NOT NULL ,
    value                   VARCHAR(256) NOT NULL,
    name                    VARCHAR(256) ,
    description             VARCHAR(256) ,
    updated_at              DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY  (tag_name,value)
)ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_string_enum;

CREATE TABLE IF NOT EXISTS ch_int_enum (
    tag_name                VARCHAR(256) NOT NULL,
    value                   INTEGER DEFAULT 0,
    name                    VARCHAR(256) ,
    description             VARCHAR(256) ,
    updated_at              DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY  (tag_name,value)
)ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_int_enum;

CREATE TABLE IF NOT EXISTS dial_test_task (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                    VARCHAR(256) NOT NULL,
    protocol                INTEGER NOT NULL COMMENT '1.ICMP',
    host                    VARCHAR(256) NOT NULL COMMENT 'dial test address',
    overtime_time           INTEGER DEFAULT 2000 COMMENT 'unit: ms',
    payload                 INTEGER DEFAULT 64,
    ttl                     SMALLINT DEFAULT 64,
    dial_location           VARCHAR(256) NOT NULL,
    dial_frequency          INTEGER DEFAULT 1000 COMMENT 'unit: ms',
    pcap                    MEDIUMBLOB,
    created_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE dial_test_task;

CREATE TABLE IF NOT EXISTS ch_chost_cloud_tag (
    `id`            INTEGER NOT NULL,
    `key`           VARCHAR(256) NOT NULL,
    `value`         VARCHAR(256),
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`, `key`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_chost_cloud_tag;

CREATE TABLE IF NOT EXISTS ch_pod_ns_cloud_tag (
    `id`            INTEGER NOT NULL,
    `key`           VARCHAR(256) NOT NULL,
    `value`         VARCHAR(256),
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`, `key`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_pod_ns_cloud_tag;

CREATE TABLE IF NOT EXISTS ch_chost_cloud_tags (
    `id`            INTEGER NOT NULL PRIMARY KEY,
    `cloud_tags`    TEXT,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_chost_cloud_tags;

CREATE TABLE IF NOT EXISTS ch_pod_ns_cloud_tags (
    `id`            INTEGER NOT NULL PRIMARY KEY,
    `cloud_tags`    TEXT,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_pod_ns_cloud_tags;

CREATE TABLE IF NOT EXISTS ch_os_app_tag (
    `pid`           INTEGER NOT NULL,
    `key`           VARCHAR(256) NOT NULL,
    `value`         VARCHAR(256),
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`pid`, `key`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_os_app_tag;

CREATE TABLE IF NOT EXISTS ch_os_app_tags (
    `pid`           INTEGER NOT NULL PRIMARY KEY,
    `os_app_tags`   TEXT,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_os_app_tags;

CREATE TABLE IF NOT EXISTS ch_gprocess (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    icon_id                 INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_gprocess;
