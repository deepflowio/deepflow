-- ============================================================================
-- SECTION HIERARCHY
-- System
--   Controllers
--   Agents
--   Analyzers
--   Authorization
-- Assets
--   Clouds
--   Network Services
--   Storage Services
--   Kubernetes
--   Processes
--   Custom Service
--   Others
-- Genesis
-- ClickHouse Dictionary
-- NPC/PCAP
-- Alerts/Reports
-- Prometheus
-- Business
-- ============================================================================

-- System
-- Controllers
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

-- Agents
CREATE TABLE IF NOT EXISTS vtap_repo (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(512),
    arch                VARCHAR(256) DEFAULT '',
    os                  VARCHAR(256) DEFAULT '',
    branch              VARCHAR(256) DEFAULT '',
    rev_count           VARCHAR(256) DEFAULT '',
    commit_id           VARCHAR(256) DEFAULT '',
    image               LONGBLOB,
    k8s_image           VARCHAR(512) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COMMENT='store deepflow-agent for easy upgrade';
TRUNCATE TABLE vtap_repo;

CREATE TABLE IF NOT EXISTS az_controller_connection (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    az                      CHAR(64) DEFAULT 'ALL',
    region                  CHAR(64) DEFAULT 'ffffffff-ffff-ffff-ffff-ffffffffffff',
    controller_ip           CHAR(64),
    lcuuid                  CHAR(64)
)ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE az_controller_connection;

CREATE TABLE IF NOT EXISTS vtap_group (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    team_id                 INTEGER DEFAULT 1,
    user_id                 INTEGER DEFAULT 1,
    name                    VARCHAR(64) NOT NULL,
    created_at              DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    lcuuid                  CHAR(64),
    license_functions       CHAR(64),
    short_uuid              CHAR(32)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE vtap_group;

CREATE TABLE IF NOT EXISTS vtap_group_configuration (
    id                                      INTEGER        NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id                                 INTEGER        DEFAULT 1,
    team_id                                 INTEGER        DEFAULT 1,
    max_collect_pps                         INTEGER        DEFAULT NULL,
    max_npb_bps                             BIGINT         DEFAULT NULL     COMMENT 'unit: bps',
    max_cpus                                INTEGER        DEFAULT NULL,
    max_millicpus                           INTEGER        DEFAULT NULL,
    max_memory                              INTEGER        DEFAULT NULL     COMMENT 'unit: M',
    platform_sync_interval                  INTEGER        DEFAULT NULL,
    sync_interval                           INTEGER        DEFAULT NULL,
    stats_interval                          INTEGER,
    rsyslog_enabled                         TINYINT(1)     COMMENT '0: disabled 1: enabled',
    system_load_circuit_breaker_threshold   FLOAT(8,2)     DEFAULT NULL,
    system_load_circuit_breaker_recover     FLOAT(8,2)     DEFAULT NULL,
    system_load_circuit_breaker_metric      CHAR(64)       DEFAULT NULL,
    max_tx_bandwidth                        BIGINT         COMMENT 'unit: bps',
    bandwidth_probe_interval                INTEGER,
    tap_interface_regex                     TEXT,
    max_escape_seconds                      INTEGER,
    mtu                                     INTEGER,
    output_vlan                             INTEGER        DEFAULT NULL,
    collector_socket_type                   CHAR(64),
    compressor_socket_type                  CHAR(64),
    npb_socket_type                         CHAR(64),
    npb_vlan_mode                           INTEGER,
    collector_enabled                       TINYINT(1)     COMMENT '0: disabled 1: enabled',
    vtap_flow_1s_enabled                    TINYINT(1)     COMMENT '0: disabled 1: enabled',
    l4_log_tap_types                        TEXT           COMMENT 'tap type info, separate by ","',
    npb_dedup_enabled                       TINYINT(1)     COMMENT '0: disabled 1: enabled',
    platform_enabled                        TINYINT(1)     COMMENT '0: disabled 1: enabled',
    if_mac_source                           INTEGER        COMMENT '0: 接口MAC 1: 接口名称 2: 虚拟机MAC解析',
    vm_xml_path                             TEXT,
    extra_netns_regex                       TEXT,
    nat_ip_enabled                          TINYINT(1)     COMMENT '0: disabled 1: enabled',
    capture_packet_size                     INTEGER,
    inactive_server_port_enabled            TINYINT(1)     COMMENT '0: disabled 1: enabled',
    inactive_ip_enabled                     TINYINT(1)     COMMENT '0: disabled 1: enabled',
    vtap_group_lcuuid                       CHAR(64)       DEFAULT NULL,
    log_threshold                           INTEGER,
    log_level                               CHAR(64),
    log_retention                           INTEGER,
    http_log_proxy_client                   CHAR(64),
    http_log_trace_id                       TEXT           DEFAULT NULL,
    l7_log_packet_size                      INTEGER,
    l4_log_collect_nps_threshold            INTEGER,
    l7_log_collect_nps_threshold            INTEGER,
    l7_metrics_enabled                      TINYINT(1)     COMMENT '0: disabled 1: enabled',
    l7_log_store_tap_types                  TEXT           COMMENT 'l7 log store tap types, separate by ","',
    l4_log_ignore_tap_sides                 TEXT           COMMENT 'separate by ","',
    l7_log_ignore_tap_sides                 TEXT           COMMENT 'separate by ","',
    decap_type                              TEXT           COMMENT 'separate by ","',
    capture_socket_type                     INTEGER,
    capture_bpf                             VARCHAR(512),
    tap_mode                                INTEGER        COMMENT '0: local 1: virtual mirror 2: physical mirror',
    thread_threshold                        INTEGER,
    process_threshold                       INTEGER,
    ntp_enabled                             TINYINT(1)     COMMENT '0: disabled 1: enabled',
    l4_performance_enabled                  TINYINT(1)     COMMENT '0: disabled 1: enabled',
    pod_cluster_internal_ip                 TINYINT(1)     COMMENT '0: 所有集群 1: 采集器所在集群',
    domains                                 TEXT           COMMENT 'domains info, separate by ","',
    http_log_span_id                        TEXT           DEFAULT NULL,
    http_log_x_request_id                   CHAR(64),
    sys_free_memory_metric                  CHAR(64),
    sys_free_memory_limit                   INTEGER        DEFAULT NULL     COMMENT 'unit: %',
    log_file_size                           INTEGER        DEFAULT NULL     COMMENT 'unit: MB',
    external_agent_http_proxy_enabled       TINYINT(1)     COMMENT '0: disabled 1: enabled',
    external_agent_http_proxy_port          INTEGER        DEFAULT NULL,
    proxy_controller_port                   INTEGER        DEFAULT NULL,
    analyzer_port                           INTEGER        DEFAULT NULL,
    proxy_controller_ip                     VARCHAR(128),
    analyzer_ip                             VARCHAR(128),
    wasm_plugins                            TEXT           COMMENT 'wasm_plugin info, separate by ","',
    so_plugins                              TEXT           COMMENT 'so_plugin info, separate by ","',
    yaml_config                             TEXT,
    lcuuid                                  CHAR(64)
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE vtap_group_configuration;

CREATE TABLE IF NOT EXISTS agent_group_configuration (
    id    INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    lcuuid CHAR(64) NOT NULL,
    agent_group_lcuuid CHAR(64) NOT NULL,
    yaml   LONGTEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE agent_group_configuration;

CREATE TABLE IF NOT EXISTS agent_group_configuration_changelog (
    id                              INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    agent_group_configuration_id    INTEGER NOT NULL,
    user_id                         INTEGER NOT NULL,
    remarks                         TEXT NOT NULL,
    yaml_diff                       MEDIUMTEXT NOT NULL,
    lcuuid                          CHAR(64) NOT NULL,
    created_at                      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                      TIMESTAMP NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE agent_group_configuration_changelog;

CREATE TABLE IF NOT EXISTS vtap (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                    VARCHAR(256) NOT NULL,
    raw_hostname            VARCHAR(256),
    `owner`                 varchar(64) DEFAULT '',
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
    exceptions              BIGINT UNSIGNED DEFAULT 0,
    vtap_lcuuid             CHAR(64) DEFAULT NULL,
    vtap_group_lcuuid       CHAR(64) DEFAULT NULL,
    cpu_num                 INTEGER DEFAULT 0 COMMENT 'logical number of cpu',
    memory_size             BIGINT DEFAULT 0,
    grpc_buffer_size        BIGINT DEFAULT 0,
    arch                    VARCHAR(256),
    os                      VARCHAR(256),
    kernel_version          VARCHAR(256),
    process_name            VARCHAR(256),
    current_k8s_image       VARCHAR(512),
    license_type            INTEGER COMMENT '1: A类 2: B类 3: C类',
    license_functions       CHAR(64) COMMENT 'separated by ,; 1: 流量分发 2: 网络监控 3: 应用监控',
    enable_features         CHAR(64) DEFAULT NULL COMMENT 'separated by ,',
    disable_features        CHAR(64) DEFAULT NULL COMMENT 'separated by ,',
    follow_group_features   CHAR(64) DEFAULT NULL COMMENT 'separated by ,',
    tap_mode                INTEGER,
    team_id                 INTEGER,
    expected_revision       TEXT,
    upgrade_package         TEXT,
    lcuuid                  CHAR(64)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE vtap;

CREATE TABLE IF NOT EXISTS kubernetes_cluster (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    cluster_id              VARCHAR(256) NOT NULL ,
    value                   VARCHAR(256) NOT NULL,
    updated_time            DATETIME DEFAULT NULL,
    created_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    synced_at               DATETIME DEFAULT NULL,
    unique (cluster_id)
)ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE kubernetes_cluster;

CREATE TABLE IF NOT EXISTS sys_configuration (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    param_name          CHAR(64) NOT NULL,
    value               VARCHAR(256),
    comments            TEXT,
    lcuuid              CHAR(64)
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE sys_configuration;

CREATE TABLE IF NOT EXISTS plugin (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(256) NOT NULL,
    type                INTEGER NOT NULL COMMENT '1: wasm 2: so 3: lua',
    user_name           INTEGER NOT NULL DEFAULT 1 COMMENT '1: agent 2: server',
    image               LONGBLOB NOT NULL,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE INDEX name_index(name)
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COMMENT='store plugins for sending to vtap';
TRUNCATE TABLE plugin;

-- Analyzers
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

CREATE TABLE IF NOT EXISTS az_analyzer_connection (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    az                      CHAR(64) DEFAULT 'ALL',
    region                  CHAR(64) DEFAULT 'ffffffff-ffff-ffff-ffff-ffffffffffff',
    analyzer_ip             CHAR(64),
    lcuuid                  CHAR(64)
)ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE az_analyzer_connection;

CREATE TABLE IF NOT EXISTS data_source (
    id                          INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    display_name                CHAR(64),
    data_table_collection       CHAR(64),
    state                       INTEGER DEFAULT 1 COMMENT '0: Exception 1: Normal',
    base_data_source_id         INTEGER,
    interval_time             INTEGER NOT NULL COMMENT 'uint: s',
    retention_time              INTEGER NOT NULL COMMENT 'uint: hour',
    query_time                  INTEGER DEFAULT 0 COMMENT 'uint: minute',
    summable_metrics_operator   CHAR(64),
    unsummable_metrics_operator CHAR(64),
    updated_at              DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    lcuuid                  CHAR(64)
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE data_source;

-- Authorization
CREATE TABLE IF NOT EXISTS voucher (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    status              INTEGER DEFAULT 0,
    name                VARCHAR(256) DEFAULT NULL,
    value               blob,
    lcuuid              CHAR(64) DEFAULT NULL
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE voucher;

CREATE TABLE IF NOT EXISTS license_func_log (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    team_id                 INTEGER DEFAULT 1,
    agent_id                INTEGER NOT NULL,
    agent_name              VARCHAR(256) NOT NULL,
    user_id                 INTEGER NOT NULL,
    license_function        INTEGER NOT NULL COMMENT '1.traffic distribution 2.network monitoring 3.call monitoring 4.function monitoring 5.application monitoring 6.indicator monitoring 7.database monitoring 8.log monitoring 9.max',
    enabled                 INTEGER NOT NULL COMMENT '0.false 1.true',
    agent_group_name        VARCHAR(64) DEFAULT NULL,
    agent_group_operation   TINYINT(1) DEFAULT NULL COMMENT '0.follow 1.update', 
    created_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE license_func_log;

CREATE TABLE IF NOT EXISTS mail_server (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    status                  int NOT NULL ,
    host                    TEXT NOT NULL,
    port                    int Not NULL,
    user_name               TEXT NOT NULL,
    password                TEXT NOT NULL,
    security                TEXT Not NULL,
    ntlm_enabled            int,
    ntlm_name               TEXT,
    ntlm_password           TEXT,
    lcuuid                  CHAR(64) DEFAULT ''
)ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE mail_server;

-- Assets
-- Clouds
CREATE TABLE IF NOT EXISTS domain (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    team_id             INTEGER DEFAULT 1,
    user_id             INTEGER DEFAULT 1,
    name                VARCHAR(64),
    icon_id             INTEGER,
    display_name        VARCHAR(64) DEFAULT '',
    cluster_id          CHAR(64),
    ip                  VARCHAR(64),
    role                INTEGER DEFAULT 0 COMMENT '1.BSS 2.OSS 3.OpenStack 4.VSphere',
    type                INTEGER DEFAULT 0 COMMENT '1.openstack 2.vsphere 3.nsp 4.tencent 5.filereader 6.aws 8.zstack 9.aliyun 10.huawei prv 11.k8s 12.simulation 13.huawei 14.qingcloud 15.qingcloud_private 16.F5 17.CMB_CMDB 18.azure 19.apsara_stack 20.tencent_tce 21.qingcloud_k8s 22.kingsoft_private 23.genesis 24.microsoft_acs 25.baidu_bce',
    public_ip           VARCHAR(64) DEFAULT NULL,
    config              TEXT,
    error_msg           TEXT,
    enabled             INTEGER NOT NULL DEFAULT '1' COMMENT '0.false 1.true',
    state               INTEGER NOT NULL DEFAULT '1' COMMENT '1.normal 2.deleting 3.exception 4.warning 5.no_license',
    exceptions          INTEGER UNSIGNED DEFAULT 0,
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
    team_id             INTEGER DEFAULT 1,
    user_id             INTEGER DEFAULT 1,
    domain              CHAR(64) DEFAULT '',
    name                VARCHAR(64) DEFAULT '',
    display_name        VARCHAR(64) DEFAULT '',
    create_method       INTEGER DEFAULT 0 COMMENT '0.learning 1.user_defined',
    cluster_id          CHAR(64) DEFAULT '',
    config              TEXT,
    error_msg           TEXT,
    enabled             INTEGER NOT NULL DEFAULT '1' COMMENT '0.false 1.true',
    state               INTEGER NOT NULL DEFAULT '1' COMMENT '1.normal 2.deleting 3.exception 4.warning 5.no_license',
    exceptions          INTEGER UNSIGNED DEFAULT 0,
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
    content             LONGTEXT,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    compressed_content  LONGBLOB
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE domain_additional_resource;

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

-- Computes
CREATE TABLE IF NOT EXISTS vm (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    state               INTEGER NOT NULL COMMENT '0.Temp 1.Creating 2.Created 3.To run 4.Running 5.To suspend 6.Suspended 7.To resume 8. To stop 9.Stopped 10.Modifing 11.Exception 12.Destroying',
    name                VARCHAR(256) DEFAULT '',
    label               CHAR(64) DEFAULT '',
    ip                  CHAR(64) DEFAULT '',
    vl2id               INTEGER DEFAULT 0,
    hostname            CHAR(64) DEFAULT '',
    create_method       INTEGER DEFAULT 0 COMMENT '0.learning 1.user_defined',
    htype               INTEGER DEFAULT 1 COMMENT '1.vm-c 2.bm-c 3.vm-n 4.bm-n 5.vm-s 6.bm-s',
    launch_server       CHAR(64) DEFAULT '',
    host_id             INTEGER DEFAULT 0,
    learned_cloud_tags  TEXT,
    custom_cloud_tags   TEXT,
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
    INDEX launch_server_index(launch_server),
    INDEX epc_id_index(epc_id),
    INDEX az_index(az),
    INDEX region_index(region),
    INDEX id_index(`id`)
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE vm;

CREATE TABLE IF NOT EXISTS host_device (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    type                INTEGER COMMENT '1.Server 3.Gateway 4.DFI',
    state               INTEGER COMMENT '0.Temp 1.Creating 2.Complete 3.Modifying 4.Exception',
    name                VARCHAR(256) DEFAULT '',
    alias               CHAR(64) DEFAULT '',
    description         VARCHAR(256) DEFAULT '',
    ip                  CHAR(64) DEFAULT '',
    hostname            CHAR(64) DEFAULT '',
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
    uid                 CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    synced_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE host_device;

-- Networks
CREATE TABLE IF NOT EXISTS epc (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    userid              INTEGER DEFAULT 0,
    name                VARCHAR(256) DEFAULT '',
    create_method       INTEGER DEFAULT 0 COMMENT '0.learning 1.user_defined',
    label               VARCHAR(64) DEFAULT '',
    `owner`             VARCHAR(64) DEFAULT '',
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
    deleted_at          DATETIME DEFAULT NULL,
    INDEX region_index(region)
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE epc;

CREATE TABLE IF NOT EXISTS vl2 (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
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
    INDEX region_index(region),
    UNIQUE INDEX lcuuid_index(lcuuid)
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=4096 /* reset in init_auto_increment */;
TRUNCATE TABLE vl2;

CREATE TABLE IF NOT EXISTS vl2_net (
    id                  INTEGER NOT NULL AUTO_INCREMENT,
    prefix              CHAR(64) DEFAULT '',
    netmask             CHAR(64) DEFAULT '',
    vl2id               INTEGER DEFAULT 0,
    net_index           INTEGER DEFAULT 0,
    name                VARCHAR(256) DEFAULT '',
    label               VARCHAR(64) DEFAULT '',
    sub_domain          CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE vl2_net;

CREATE TABLE IF NOT EXISTS vnet (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
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
    INDEX state_server_index(state, gw_launch_server)
)ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=256 /* reset in init_auto_increment */;
TRUNCATE TABLE vnet;

CREATE TABLE IF NOT EXISTS routing_table (
    id                  INTEGER NOT NULL auto_increment PRIMARY KEY,
    vnet_id             INTEGER,
    destination         TEXT,
    nexthop_type        TEXT,
    nexthop             TEXT,
    domain              CHAR(64) DEFAULT '',
    lcuuid              CHAR(64),
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX vnet_id_index(vnet_id)
)engine=innodb AUTO_INCREMENT=1  DEFAULT CHARSET=utf8;
TRUNCATE TABLE routing_table;

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

CREATE TABLE IF NOT EXISTS vinterface (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                CHAR(64) DEFAULT '',
    ifindex             INTEGER NOT NULL,
    state               INTEGER NOT NULL COMMENT '1. Attached 2.Detached 3.Exception',
    create_method       INTEGER DEFAULT 0 COMMENT '0.learning 1.user_defined',
    iftype              INTEGER DEFAULT 0 COMMENT '0.Unknown 1.Control 2.Service 3.WAN 4.LAN 5.Trunk 6.Tap 7.Tool',
    mac                 CHAR(32) DEFAULT '',
    vmac                CHAR(32) DEFAULT '',
    tap_mac             CHAR(32) DEFAULT '',
    subnetid            INTEGER DEFAULT 0 COMMENT 'vl2 id',
    vlantag             INTEGER DEFAULT 0,
    devicetype          INTEGER COMMENT 'Type 0.unknown 1.vm 2.vgw 3.third-party-device 4.vmwaf 5.NSP-vgateway 6.host-device 7.network-device 9.DHCP-port 10.pod 11.pod_service 12. redis_instance 13. rds_instance 14. pod_node 15. load_balance 16. nat_gateway',
    deviceid            INTEGER COMMENT 'unknown: Senseless ID, vm: vm ID, vgw/NSP-vgateway: vnet ID, third-party-device: third_party_device ID, vmwaf: vmwaf ID, host-device: host_device ID, network-device: network_device ID',
    netns_id            INTEGER UNSIGNED DEFAULT 0,
    vtap_id             INTEGER DEFAULT 0,
    epc_id              INTEGER DEFAULT 0,
    sub_domain          CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    region              CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX epc_id_index(epc_id),
    INDEX mac_index(mac)
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE vinterface;

CREATE TABLE IF NOT EXISTS vinterface_ip (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ip                  CHAR(64) DEFAULT '',
    netmask             CHAR(64) DEFAULT '',
    gateway             CHAR(64) DEFAULT '',
    create_method       INTEGER DEFAULT 0 COMMENT '0.learning 1.user_defined',
    vl2id               INTEGER DEFAULT 0,
    vl2_net_id          INTEGER DEFAULT 0,
    net_index           INTEGER DEFAULT 0,
    sub_domain          CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    vifid               INTEGER DEFAULT 0,
    isp                 INTEGER DEFAULT 0 COMMENT 'Used for multi-ISP access',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX ip_index(`ip`),
    INDEX vifid_index(`vifid`)
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE vinterface_ip;

CREATE TABLE IF NOT EXISTS ip_resource (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
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
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX ip_index(`ip`),
    INDEX vifid_index(`vifid`)
)ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE ip_resource;

CREATE TABLE IF NOT EXISTS floatingip (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    domain              CHAR(64) DEFAULT '',
    region              CHAR(64) DEFAULT '',
    epc_id              INTEGER DEFAULT 0,
    vl2_id              INTEGER,
    vm_id               INTEGER,
    ip                  CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE floatingip;

CREATE TABLE IF NOT EXISTS vip (
    id          INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    lcuuid      CHAR(64),
    ip          CHAR(64),
    domain      CHAR(64) DEFAULT '',
    vtap_id     INTEGER,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=innodb DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1;
TRUNCATE TABLE vip;

-- Network Services
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
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX nat_id_index(nat_id)
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE nat_rule;

CREATE TABLE IF NOT EXISTS nat_vm_connection (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    nat_id              INTEGER,
    vm_id               INTEGER,
    domain              CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE nat_vm_connection;

CREATE TABLE IF NOT EXISTS lb (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    label               CHAR(64) DEFAULT '',
    model               INTEGER DEFAULT 0 COMMENT '1.Internal 2.External',
    vip                 TEXT COMMENT 'separated by ,',
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
    deleted_at          DATETIME DEFAULT NULL,
    INDEX lb_id_index(lb_id)
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
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX lb_id_index(lb_id)
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE lb_target_server;

CREATE TABLE IF NOT EXISTS lb_vm_connection (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    lb_id               INTEGER,
    vm_id               INTEGER,
    domain              CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE lb_vm_connection;

CREATE TABLE IF NOT EXISTS peer_connection (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    label               CHAR(64) DEFAULT '',
    team_id             INTEGER NOT NULL,
    local_epc_id        INTEGER DEFAULT NULL,
    remote_epc_id       INTEGER DEFAULT NULL,
    local_domain        CHAR(64) NOT NULL,
    remote_domain       CHAR(64) NOT NULL,
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

-- Storage Services
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

-- Kubernetes
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
    uid                 CHAR(64) DEFAULT '',
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
    hostname            CHAR(64) DEFAULT '',
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
    deleted_at          DATETIME DEFAULT NULL,
    INDEX pod_cluster_id_index(pod_cluster_id),
    INDEX epc_id_index(epc_id),
    INDEX az_index(az),
    INDEX region_index(region)
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE pod_node;

CREATE TABLE IF NOT EXISTS vm_pod_node_connection (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    vm_id               INTEGER,
    pod_node_id         INTEGER,
    domain              CHAR(64) DEFAULT '',
    sub_domain          CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE vm_pod_node_connection;

CREATE TABLE IF NOT EXISTS pod_namespace (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    learned_cloud_tags  TEXT,
    custom_cloud_tags   TEXT,
    pod_cluster_id      INTEGER DEFAULT NULL,
    az                  CHAR(64) DEFAULT '',
    region              CHAR(64) DEFAULT '',
    sub_domain          CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    uid                 CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE pod_namespace;

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
    domain              CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX pod_ingress_id_index(pod_ingress_id)
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
    domain              CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE pod_ingress_rule_backend;

CREATE TABLE IF NOT EXISTS pod_service (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    label               TEXT COMMENT 'separated by ,',
    annotation          TEXT COMMENT 'separated by ,',
    alias               CHAR(64) DEFAULT '',
    type                INTEGER DEFAULT NULL COMMENT '1: ClusterIP 2: NodePort 3: LoadBalancer',
    selector            TEXT COMMENT 'separated by ,',
    external_ip         TEXT COMMENT 'separated by ,',
    service_cluster_ip  CHAR(64) DEFAULT '',
    compressed_metadata MEDIUMBLOB COMMENT 'compressed yaml',
    metadata_hash       CHAR(64) DEFAULT '',
    compressed_spec     MEDIUMBLOB COMMENT 'compressed yaml',
    spec_hash           CHAR(64) DEFAULT '',
    pod_ingress_id      INTEGER DEFAULT NULL,
    pod_namespace_id    INTEGER DEFAULT NULL,
    pod_cluster_id      INTEGER DEFAULT NULL,
    epc_id              INTEGER DEFAULT NULL,
    az                  CHAR(64) DEFAULT '',
    region              CHAR(64) DEFAULT '',
    sub_domain          CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    uid                 CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL,
    INDEX pod_ingress_id_index(pod_ingress_id),
    INDEX pod_namespace_id_index(pod_namespace_id),
    INDEX pod_cluster_id_index(pod_cluster_id),
    INDEX domain_index(`domain`)
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
    domain              CHAR(64) DEFAULT '',
    lcuuid              CHAR(64),
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX pod_service_id_index(pod_service_id)
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE pod_service_port;

CREATE TABLE IF NOT EXISTS pod_group (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    alias               CHAR(64) DEFAULT '',
    type                INTEGER DEFAULT NULL COMMENT '1: Deployment 2: StatefulSet 3: ReplicationController',
    pod_num             INTEGER DEFAULT 1,
    label               TEXT COMMENT 'separated by ,',
    network_mode        INTEGER DEFAULT 1 COMMENT '1: Pod network 2: Host network',
    compressed_metadata MEDIUMBLOB COMMENT 'compressed yaml',
    metadata_hash       CHAR(64) DEFAULT '',
    compressed_spec     MEDIUMBLOB COMMENT 'compressed yaml',
    spec_hash           CHAR(64) DEFAULT '',
    pod_namespace_id    INTEGER DEFAULT NULL,
    pod_cluster_id      INTEGER DEFAULT NULL,
    az                  CHAR(64) DEFAULT '',
    region              CHAR(64) DEFAULT '',
    sub_domain          CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    uid                 CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL,
    INDEX pod_namespace_id_index(pod_namespace_id),
    INDEX pod_cluster_id_index(pod_cluster_id)
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE pod_group;

CREATE TABLE IF NOT EXISTS pod_group_port (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    protocol            CHAR(64) DEFAULT '',
    port                INTEGER,
    pod_group_id        INTEGER DEFAULT NULL,
    pod_service_id      INTEGER DEFAULT NULL,
    sub_domain          CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE pod_group_port;

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
    deleted_at          DATETIME DEFAULT NULL,
    INDEX pod_group_id_index(pod_group_id),
    INDEX pod_namespace_id_index(pod_namespace_id)
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE pod_rs;

CREATE TABLE IF NOT EXISTS pod (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    alias               CHAR(64) DEFAULT '',
    label               TEXT COMMENT 'separated by ,',
    annotation          TEXT COMMENT 'separated by ,',
    env                 TEXT COMMENT 'separated by ,',
    container_ids       TEXT COMMENT 'separated by ,',
    state               INTEGER NOT NULL COMMENT '0.Exception 1.Running',
    pod_rs_id           INTEGER DEFAULT NULL,
    pod_group_id        INTEGER DEFAULT NULL,
    pod_service_id      INTEGER DEFAULT 0,
    pod_namespace_id    INTEGER DEFAULT NULL,
    pod_node_id         INTEGER DEFAULT NULL,
    pod_cluster_id      INTEGER DEFAULT NULL,
    epc_id              INTEGER DEFAULT NULL,
    az                  CHAR(64) DEFAULT '',
    region              CHAR(64) DEFAULT '',
    sub_domain          CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    uid                 CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL,
    INDEX state_index(state),
    INDEX pod_rs_id_index(pod_rs_id),
    INDEX pod_group_id_index(pod_group_id),
    INDEX pod_node_id_index(pod_node_id),
    INDEX pod_namespace_id_index(pod_namespace_id),
    INDEX pod_cluster_id_index(pod_cluster_id),
    INDEX epc_id_index(epc_id),
    INDEX az_index(az),
    INDEX region_index(region),
    INDEX domain_index(domain)
) ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE pod;

CREATE TABLE IF NOT EXISTS config_map (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(256) NOT NULL,
    compressed_data     MEDIUMBLOB COMMENT 'compressed yaml',
    data_hash           CHAR(64) DEFAULT '',
    pod_namespace_id    INTEGER NOT NULL,
    pod_cluster_id      INTEGER NOT NULL,
    epc_id              INTEGER NOT NULL,
    az                  CHAR(64) DEFAULT '',
    region              CHAR(64) DEFAULT '',
    sub_domain          CHAR(64) DEFAULT '',
    domain              CHAR(64) NOT NULL,
    lcuuid              CHAR(64) NOT NULL,
    synced_at           DATETIME DEFAULT NULL,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX data_hash_index(data_hash),
    INDEX domain_index(domain)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE config_map;

CREATE TABLE IF NOT EXISTS pod_group_config_map_connection (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    pod_group_id        INTEGER NOT NULL,
    config_map_id   INTEGER NOT NULL,
    sub_domain          CHAR(64) DEFAULT '',
    domain              CHAR(64) NOT NULL,
    lcuuid              CHAR(64) NOT NULL,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX pod_group_id_index(pod_group_id),
    INDEX config_map_id_index(config_map_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE pod_group_config_map_connection;

-- Processes
CREATE TABLE IF NOT EXISTS process (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                TEXT,
    vtap_id             INTEGER NOT NULL DEFAULT 0,
    pid                 INTEGER NOT NULL,
    gid                 INTEGER NOT NULL,
    devicetype          INTEGER,
    deviceid            INTEGER,
    pod_group_id        INTEGER,
    pod_node_id         INTEGER,
    vm_id               INTEGER,
    epc_id              INTEGER,
    process_name        TEXT,
    command_line        TEXT,
    user_name           VARCHAR(256) DEFAULT '',
    start_time          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    os_app_tags         TEXT COMMENT 'separated by ,',
    netns_id            INTEGER UNSIGNED DEFAULT 0,
    sub_domain          CHAR(64) DEFAULT '',
    domain              CHAR(64) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    container_id        CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL,
    INDEX domain_sub_domain_gid_updated_at_index(domain, sub_domain, gid, updated_at DESC),
    INDEX deleted_at_index(deleted_at)
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE process;

-- Custom Service
CREATE TABLE IF NOT EXISTS custom_service (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(128) NOT NULL,
    type                INTEGER DEFAULT 0 COMMENT '0: unknown 1: IP 2: PORT 3: chost 4: pod_service 5: pod_group 6: host',
    match_type          INTEGER DEFAULT 1 COMMENT '0: unkonwn 1: name match 2: uid match',
    epc_ids             TEXT COMMENT 'separated by ,',
    pod_cluster_ids     TEXT COMMENT 'separated by ,',
    pod_namespace_ids   TEXT COMMENT 'separated by ,',
    resources           TEXT COMMENT 'separated by ,',
    domain_id           INTEGER DEFAULT 0,
    domain              CHAR(64) DEFAULT '' COMMENT 'reserved for backend',
    team_id             INTEGER DEFAULT 1,
    service_group_name  VARCHAR(128) DEFAULT '',
    lcuuid              CHAR(64) DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE INDEX name_index(name)
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE custom_service;

-- Others
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

-- Genesis
CREATE TABLE IF NOT EXISTS genesis_host (
    lcuuid      CHAR(64),
    hostname    VARCHAR(256),
    ip          CHAR(64),
    vtap_id     INTEGER,
    node_ip     CHAR(48),
    PRIMARY KEY (`lcuuid`,`vtap_id`, `node_ip`)
) ENGINE=innodb DEFAULT CHARSET=utf8mb4;
TRUNCATE TABLE genesis_host;

CREATE TABLE IF NOT EXISTS genesis_vm (
    lcuuid          CHAR(64),
    name            VARCHAR(256),
    label           CHAR(64),
    vpc_lcuuid      CHAR(64),
    launch_server   CHAR(64),
    node_ip         CHAR(48),
    state           INTEGER,
    vtap_id         INTEGER,
    created_at      DATETIME,
    PRIMARY KEY (`lcuuid`,`vtap_id`, `node_ip`)
) ENGINE=innodb DEFAULT CHARSET=utf8mb4;
TRUNCATE TABLE genesis_vm;

CREATE TABLE IF NOT EXISTS genesis_vip (
    lcuuid      CHAR(64),
    ip          CHAR(64),
    vtap_id     INTEGER,
    node_ip     CHAR(48),
    PRIMARY KEY (`lcuuid`,`vtap_id`, `node_ip`)
) ENGINE=innodb DEFAULT CHARSET=utf8mb4;
TRUNCATE TABLE genesis_vip;

CREATE TABLE IF NOT EXISTS genesis_vpc (
    lcuuid          CHAR(64),
    node_ip         CHAR(48),
    vtap_id         INTEGER,
    name            VARCHAR(256),
    PRIMARY KEY (`lcuuid`,`vtap_id`, `node_ip`)
) ENGINE=innodb DEFAULT CHARSET=utf8mb4;
TRUNCATE TABLE genesis_vpc;

CREATE TABLE IF NOT EXISTS genesis_network (
    name            VARCHAR(256),
    lcuuid          CHAR(64),
    segmentation_id INTEGER,
    net_type        INTEGER,
    external        TINYINT(1),
    vpc_lcuuid      CHAR(64),
    vtap_id         INTEGER,
    node_ip         CHAR(48),
    PRIMARY KEY (`lcuuid`,`vtap_id`, `node_ip`)
) ENGINE=innodb DEFAULT CHARSET=utf8mb4;
TRUNCATE TABLE genesis_network;

CREATE TABLE IF NOT EXISTS genesis_port (
    lcuuid          CHAR(64),
    type            INTEGER,
    device_type     INTEGER,
    mac             CHAR(32),
    device_lcuuid   CHAR(64),
    network_lcuuid  CHAR(64),
    vpc_lcuuid      CHAR(64),
    vtap_id         INTEGER,
    node_ip         CHAR(48),
    PRIMARY KEY (`lcuuid`,`vtap_id`, `node_ip`)
) ENGINE=innodb DEFAULT CHARSET=utf8mb4;
TRUNCATE TABLE genesis_port;

CREATE TABLE IF NOT EXISTS genesis_ip (
    lcuuid              CHAR(64),
    ip                  CHAR(64),
    vinterface_lcuuid   CHAR(64),
    node_ip             CHAR(48),
    last_seen           DATETIME,
    vtap_id             INTEGER,
    masklen             INTEGER DEFAULT 0,
    PRIMARY KEY (`lcuuid`,`vtap_id`, `node_ip`)
) ENGINE=innodb DEFAULT CHARSET=utf8mb4;
TRUNCATE TABLE genesis_ip;

CREATE TABLE IF NOT EXISTS genesis_lldp (
    lcuuid                  CHAR(64),
    host_ip                 CHAR(48),
    host_interface          CHAR(64),
    node_ip                 CHAR(48),
    system_name             VARCHAR(512),
    management_address      VARCHAR(512),
    vinterface_lcuuid       VARCHAR(512),
    vinterface_description  VARCHAR(512),
    vtap_id                 INTEGER,
    last_seen               DATETIME,
    PRIMARY KEY (`lcuuid`,`vtap_id`, `node_ip`)
) ENGINE=innodb DEFAULT CHARSET=utf8mb4;
TRUNCATE TABLE genesis_lldp;

CREATE TABLE IF NOT EXISTS genesis_vinterface (
    netns_id              INTEGER UNSIGNED DEFAULT 0,
    lcuuid                CHAR(64),
    name                  CHAR(64),
    mac                   CHAR(32),
    ips                   TEXT,
    tap_name              CHAR(64),
    tap_mac               CHAR(32),
    device_lcuuid         CHAR(64),
    device_name           VARCHAR(512),
    device_type           CHAR(64),
    if_type               CHAR(64) DEFAULT '',
    host_ip               CHAR(48),
    node_ip               CHAR(48),
    last_seen             DATETIME,
    vtap_id               INTEGER,
    kubernetes_cluster_id CHAR(64),
    team_id               INTEGER DEFAULT 1,
    PRIMARY KEY (`lcuuid`,`vtap_id`, `node_ip`),
    INDEX node_ip_index(node_ip)
) ENGINE=innodb DEFAULT CHARSET=utf8mb4;
TRUNCATE TABLE genesis_vinterface;

CREATE TABLE IF NOT EXISTS genesis_process (
    netns_id            INTEGER UNSIGNED DEFAULT 0,
    vtap_id             INTEGER NOT NULL DEFAULT 0,
    pid                 INTEGER NOT NULL,
    lcuuid              CHAR(64) DEFAULT '',
    name                TEXT,
    process_name        TEXT,
    cmd_line            TEXT,
    user_name           VARCHAR(256) DEFAULT '',
    container_id        CHAR(64) DEFAULT '',
    os_app_tags         TEXT COMMENT 'separated by ,',
    node_ip             CHAR(48) DEFAULT '',
    start_time          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`lcuuid`,`vtap_id`, `node_ip`),
    INDEX node_ip_index(node_ip)
) ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE genesis_process;

CREATE TABLE IF NOT EXISTS genesis_storage (
    vtap_id     INTEGER NOT NULL PRIMARY KEY,
    node_ip     CHAR(48)
) ENGINE=innodb DEFAULT CHARSET = utf8mb4;
TRUNCATE TABLE genesis_storage;

CREATE TABLE IF NOT EXISTS genesis_cluster (
    id          CHAR(64) NOT NULL PRIMARY KEY,
    node_ip     CHAR(48)
) ENGINE=innodb DEFAULT CHARSET = utf8mb4;
TRUNCATE TABLE genesis_cluster;

-- ClickHouse dictionary
CREATE TABLE IF NOT EXISTS ch_pod_k8s_env (
    `id`               INTEGER NOT NULL,
    `key`              VARCHAR(256) NOT NULL COLLATE utf8_bin,
    `value`            VARCHAR(256),
    `l3_epc_id`        INTEGER,
    `pod_ns_id`        INTEGER,
    `team_id`          INTEGER,
    `domain_id`        INTEGER,
    `sub_domain_id`    INTEGER,
    `updated_at`       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`, `key`),
    INDEX domain_sub_domain_id_updated_at_index(domain_id, sub_domain_id, id, updated_at ASC),
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_pod_k8s_env;

CREATE TABLE IF NOT EXISTS ch_pod_k8s_envs (
    `id`               INTEGER NOT NULL PRIMARY KEY,
    `envs`             TEXT,
    `l3_epc_id`        INTEGER,
    `pod_ns_id`        INTEGER,
    `team_id`          INTEGER,
    `domain_id`        INTEGER,
    `sub_domain_id`    INTEGER,
    `updated_at`       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_pod_k8s_envs;

CREATE TABLE IF NOT EXISTS ch_app_label (
    `label_name_id`      INT(10) NOT NULL,
    `label_value_id`     INT(10) NOT NULL,
    `label_value`        TEXT,
    `updated_at`         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (label_name_id, label_value_id),
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_app_label;

CREATE TABLE IF NOT EXISTS ch_target_label (
    `metric_id`          INT(10) NOT NULL,
    `label_name_id`      INT(10) NOT NULL,
    `target_id`          INT(10) NOT NULL,
    `label_value`        VARCHAR(256) NOT NULL,
    `updated_at`         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (metric_id, label_name_id, target_id),
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_target_label;

CREATE TABLE IF NOT EXISTS ch_prometheus_label_name (
    `id`            INT(10) NOT NULL PRIMARY KEY,
    `name`          VARCHAR(256) NOT NULL,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_prometheus_label_name;

CREATE TABLE IF NOT EXISTS ch_prometheus_metric_name (
    `id`            INT(10) NOT NULL PRIMARY KEY,
    `name`          VARCHAR(256) NOT NULL,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_prometheus_metric_name;

CREATE TABLE IF NOT EXISTS ch_prometheus_metric_app_label_layout (
    `id`                        INT(10) NOT NULL PRIMARY KEY,
    `metric_name`               VARCHAR(256) NOT NULL,
    `app_label_name`            VARCHAR(256) NOT NULL,
    `app_label_column_index`    TINYINT(3) UNSIGNED NOT NULL,
    `updated_at`                TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_prometheus_metric_app_label_layout;

CREATE TABLE IF NOT EXISTS ch_prometheus_target_label_layout (
    `target_id`           INT(10) NOT NULL PRIMARY KEY,
    `target_label_names`  TEXT,
    `target_label_values` TEXT,
    `updated_at`          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_prometheus_target_label_layout;

CREATE TABLE IF NOT EXISTS ch_pod_service (
    `id`                 INTEGER NOT NULL PRIMARY KEY,
    `name`               VARCHAR(256),
    `pod_cluster_id`     INTEGER,
    `pod_ns_id`          INTEGER,
    `team_id`            INTEGER,
    `domain_id`          INTEGER,
    `sub_domain_id`      INTEGER,
    `updated_at`         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_pod_service;

CREATE TABLE IF NOT EXISTS ch_chost (
    `id`              INTEGER NOT NULL PRIMARY KEY,
    `name`            VARCHAR(256),
    `host_id`         INTEGER,
    `l3_epc_id`       INTEGER,
    `ip`              CHAR(64),
    `subnet_id`       INTEGER,
    `hostname`        VARCHAR(256),
    `team_id`         INTEGER,
    `domain_id`       INTEGER,
    `updated_at`      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_chost;

CREATE TABLE IF NOT EXISTS ch_biz_service (
    `id`                 INTEGER NOT NULL PRIMARY KEY,
    `name`               VARCHAR(256),
    `service_group_name` VARCHAR(256),
    `icon_id`            INTEGER,
    `team_id`            INTEGER,
    `domain_id`          INTEGER,
    `updated_at`         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_biz_service;

CREATE TABLE IF NOT EXISTS ch_policy (
    `tunnel_type`     INTEGER NOT NULL,
    `acl_gid`         INTEGER NOT NULL,
    `id`              INTEGER,
    `name`            VARCHAR(256),
    `team_id`         INTEGER DEFAULT 1,
    `updated_at`      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`tunnel_type`, `acl_gid`),
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_policy;

CREATE TABLE IF NOT EXISTS ch_npb_tunnel (
    `id`              INTEGER NOT NULL PRIMARY KEY,
    `name`            VARCHAR(256),
    `team_id`         INTEGER DEFAULT 1,
    `updated_at`      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_npb_tunnel;

CREATE TABLE IF NOT EXISTS ch_alarm_policy (
    `id`              INTEGER NOT NULL PRIMARY KEY,
    `name`            VARCHAR(256),
    `info`            TEXT,
    `user_id`         INTEGER,
    `team_id`         INTEGER DEFAULT 1,
    `updated_at`      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_alarm_policy;

CREATE TABLE IF NOT EXISTS ch_user (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_user;

CREATE TABLE IF NOT EXISTS ch_chost_cloud_tag (
    `id`            INTEGER NOT NULL,
    `key`           VARCHAR(256) NOT NULL COLLATE utf8_bin,
    `value`         VARCHAR(256),
    `team_id`       INTEGER,
    `domain_id`     INTEGER,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`, `key`),
    INDEX domain_sub_domain_id_updated_at_index(domain_id, id, updated_at ASC),
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_chost_cloud_tag;

CREATE TABLE IF NOT EXISTS ch_pod_ns_cloud_tag (
    `id`               INTEGER NOT NULL,
    `key`              VARCHAR(256) NOT NULL COLLATE utf8_bin,
    `value`            VARCHAR(256),
    `team_id`          INTEGER,
    `domain_id`        INTEGER,
    `sub_domain_id`    INTEGER,
    `updated_at`       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`, `key`),
    INDEX domain_sub_domain_id_updated_at_index(domain_id, sub_domain_id, id, updated_at ASC),
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_pod_ns_cloud_tag;

CREATE TABLE IF NOT EXISTS ch_chost_cloud_tags (
    `id`            INTEGER NOT NULL PRIMARY KEY,
    `cloud_tags`    TEXT,
    `team_id`       INTEGER,
    `domain_id`     INTEGER,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_chost_cloud_tags;

CREATE TABLE IF NOT EXISTS ch_pod_ns_cloud_tags (
    `id`               INTEGER NOT NULL PRIMARY KEY,
    `cloud_tags`       TEXT,
    `team_id`          INTEGER,
    `domain_id`        INTEGER,
    `sub_domain_id`    INTEGER,
    `updated_at`       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_pod_ns_cloud_tags;

CREATE TABLE IF NOT EXISTS ch_os_app_tag (
    `id`               INTEGER NOT NULL,
    `key`              VARCHAR(256) NOT NULL COLLATE utf8_bin,
    `value`            VARCHAR(256),
    `team_id`          INTEGER,
    `domain_id`        INTEGER,
    `sub_domain_id`    INTEGER,
    `updated_at`       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`, `key`),
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_os_app_tag;

CREATE TABLE IF NOT EXISTS ch_os_app_tags (
    `id`               INTEGER NOT NULL PRIMARY KEY,
    `os_app_tags`      TEXT,
    `team_id`          INTEGER,
    `domain_id`        INTEGER,
    `sub_domain_id`    INTEGER,
    `updated_at`       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_os_app_tags;

CREATE TABLE IF NOT EXISTS ch_gprocess (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    TEXT,
    icon_id                 INTEGER,
    chost_id                INTEGER,
    l3_epc_id               INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    sub_domain_id           INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_gprocess;

CREATE TABLE IF NOT EXISTS ch_pod_service_k8s_label (
    `id`               INTEGER NOT NULL,
    `key`              VARCHAR(256) NOT NULL COLLATE utf8_bin,
    `value`            VARCHAR(256),
    `l3_epc_id`        INTEGER,
    `pod_ns_id`        INTEGER,
    `team_id`          INTEGER,
    `domain_id`        INTEGER,
    `sub_domain_id`    INTEGER,
    `updated_at`       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`, `key`),
    INDEX domain_sub_domain_id_updated_at_index(domain_id, sub_domain_id, id, updated_at ASC),
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_pod_service_k8s_label;

CREATE TABLE IF NOT EXISTS ch_pod_service_k8s_labels (
    `id`               INTEGER NOT NULL PRIMARY KEY,
    `labels`           TEXT,
    `l3_epc_id`        INTEGER,
    `pod_ns_id`        INTEGER,
    `team_id`          INTEGER,
    `domain_id`        INTEGER,
    `sub_domain_id`    INTEGER,
    `updated_at`       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_pod_service_k8s_labels;

CREATE TABLE IF NOT EXISTS ch_pod_k8s_annotation (
    `id`               INTEGER NOT NULL,
    `key`              VARCHAR(256) NOT NULL COLLATE utf8_bin,
    `value`            VARCHAR(256),
    `l3_epc_id`        INTEGER,
    `pod_ns_id`        INTEGER,
    `team_id`          INTEGER,
    `domain_id`        INTEGER,
    `sub_domain_id`    INTEGER,
    `updated_at`       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`, `key`),
    INDEX domain_sub_domain_id_updated_at_index(domain_id, sub_domain_id, id, updated_at ASC),
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_pod_k8s_annotation;

CREATE TABLE IF NOT EXISTS ch_pod_k8s_annotations (
    `id`               INTEGER NOT NULL PRIMARY KEY,
    `annotations`      TEXT,
    `l3_epc_id`        INTEGER,
    `pod_ns_id`        INTEGER,
    `team_id`          INTEGER,
    `domain_id`        INTEGER,
    `sub_domain_id`    INTEGER,
    `updated_at`       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_pod_k8s_annotations;

CREATE TABLE IF NOT EXISTS ch_pod_service_k8s_annotation (
    `id`               INTEGER NOT NULL,
    `key`              VARCHAR(256) NOT NULL COLLATE utf8_bin,
    `value`            VARCHAR(256),
    `l3_epc_id`        INTEGER,
    `pod_ns_id`        INTEGER,
    `team_id`          INTEGER,
    `domain_id`        INTEGER,
    `sub_domain_id`    INTEGER,
    `updated_at`       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`, `key`),
    INDEX domain_sub_domain_id_updated_at_index(domain_id, sub_domain_id, id, updated_at ASC),
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_pod_k8s_annotation;

CREATE TABLE IF NOT EXISTS ch_pod_service_k8s_annotations (
    `id`               INTEGER NOT NULL PRIMARY KEY,
    `annotations`      TEXT,
    `l3_epc_id`        INTEGER,
    `pod_ns_id`        INTEGER,
    `team_id`          INTEGER,
    `domain_id`        INTEGER,
    `sub_domain_id`    INTEGER,
    `updated_at`       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_pod_k8s_annotations;

CREATE TABLE IF NOT EXISTS ch_string_enum (
    tag_name                VARCHAR(256) NOT NULL ,
    value                   VARCHAR(256) NOT NULL,
    name_zh                 VARCHAR(256) ,
    name_en                 VARCHAR(256) ,
    description_zh          VARCHAR(256) ,
    description_en          VARCHAR(256) ,
    updated_at              DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY  (tag_name,value),
    INDEX updated_at_index(`updated_at`)
)ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_string_enum;

CREATE TABLE IF NOT EXISTS ch_int_enum (
    tag_name                VARCHAR(256) NOT NULL,
    value                   INTEGER DEFAULT 0,
    name_zh                 VARCHAR(256) ,
    name_en                 VARCHAR(256) ,
    description_zh          VARCHAR(256) ,
    description_en          VARCHAR(256) ,
    updated_at              DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY  (tag_name,value),
    INDEX updated_at_index(`updated_at`)
)ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_int_enum;

CREATE TABLE IF NOT EXISTS ch_region (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    icon_id                 INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_region;

CREATE TABLE IF NOT EXISTS ch_az (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    icon_id                 INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_az;

CREATE TABLE IF NOT EXISTS ch_l3_epc (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    uid                     CHAR(64),
    icon_id                 INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_l3_epc;

CREATE TABLE IF NOT EXISTS ch_subnet (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    icon_id                 INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    sub_domain_id           INTEGER,
    l3_epc_id               INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_subnet;

CREATE TABLE IF NOT EXISTS ch_pod_cluster (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    icon_id                 INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    sub_domain_id           INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_pod_cluster;

CREATE TABLE IF NOT EXISTS ch_pod_node (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    pod_cluster_id          INTEGER,
    icon_id                 INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    sub_domain_id           INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_pod_node;

CREATE TABLE IF NOT EXISTS ch_pod_ns (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    icon_id                 INTEGER,
    pod_cluster_id          INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    sub_domain_id           INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_pod_ns;

CREATE TABLE IF NOT EXISTS ch_pod_group (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    pod_group_type          INTEGER DEFAULT NULL,
    icon_id                 INTEGER,
    pod_cluster_id          INTEGER,
    pod_ns_id               INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    sub_domain_id           INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_pod_group;

CREATE TABLE IF NOT EXISTS ch_pod (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    icon_id                 INTEGER,
    pod_cluster_id          INTEGER,
    pod_ns_id               INTEGER,
    pod_node_id             INTEGER,
    pod_service_id          INTEGER,
    pod_group_id            INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    sub_domain_id           INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_pod;

CREATE TABLE IF NOT EXISTS ch_device (
    devicetype              INTEGER NOT NULL,
    deviceid                INTEGER NOT NULL,
    name                    TEXT,
    uid                     CHAR(64),
    icon_id                 INTEGER,
    ip                      CHAR(64),
    hostname                VARCHAR(256),
    team_id                 INTEGER,
    domain_id               INTEGER,
    sub_domain_id           INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (devicetype, deviceid),
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_device;

CREATE TABLE IF NOT EXISTS ch_vtap_port (
    vtap_id                 INTEGER NOT NULL,
    tap_port                BIGINT NOT NULL,
    name                    VARCHAR(256),
    mac_type                INTEGER DEFAULT 1 COMMENT '1:tap_mac,2:mac',
    host_id                 INTEGER,
    host_name               VARCHAR(256),
    chost_id                INTEGER,
    chost_name              VARCHAR(256),
    pod_node_id             INTEGER,
    pod_node_name           VARCHAR(256),
    device_type             INTEGER,
    device_id               INTEGER,
    device_name             VARCHAR(256),
    icon_id                 INTEGER,
    team_id                 INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (vtap_id, tap_port),
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_vtap_port;

CREATE TABLE IF NOT EXISTS ch_tap_type (
    value                   INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256) NOT NULL,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_tap_type;

CREATE TABLE IF NOT EXISTS ch_vtap (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    type                    INTEGER,
    team_id                 INTEGER,
    host_id                 INTEGER,
    host_name               VARCHAR(256),
    chost_id                INTEGER,
    chost_name              VARCHAR(256),
    pod_node_id             INTEGER,
    pod_node_name           VARCHAR(256),
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_vtap;

CREATE TABLE IF NOT EXISTS ch_pod_k8s_label (
    `id`               INTEGER NOT NULL,
    `key`              VARCHAR(256) NOT NULL COLLATE utf8_bin,
    `value`            VARCHAR(256),
    `l3_epc_id`        INTEGER,
    `pod_ns_id`        INTEGER,
    `team_id`          INTEGER,
    `domain_id`        INTEGER,
    `sub_domain_id`    INTEGER,
    `updated_at`       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`, `key`),
    INDEX domain_sub_domain_id_updated_at_index(domain_id, sub_domain_id, id, updated_at ASC),
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_pod_k8s_label;

CREATE TABLE IF NOT EXISTS ch_pod_k8s_labels (
    `id`               INTEGER NOT NULL PRIMARY KEY,
    `labels`           TEXT,
    `l3_epc_id`        INTEGER,
    `pod_ns_id`        INTEGER,
    `team_id`          INTEGER,
    `domain_id`        INTEGER,
    `sub_domain_id`    INTEGER,
    `updated_at`       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_pod_k8s_labels;

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
    team_id             INTEGER,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (l3_epc_id, ip),
    INDEX updated_at_index(`updated_at`)
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
    l3_epc_id           INTEGER,
    l3_epc_name         VARCHAR(256),
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
    PRIMARY KEY (ip, subnet_id),
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_ip_resource;

CREATE TABLE IF NOT EXISTS ch_lb_listener (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    team_id                 INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_lb_listener;

CREATE TABLE IF NOT EXISTS ch_pod_ingress (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    pod_cluster_id          INTEGER,
    pod_ns_id               INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    sub_domain_id           INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_pod_ingress;

CREATE TABLE IF NOT EXISTS ch_node_type (
    resource_type           INTEGER NOT NULL DEFAULT 0 PRIMARY KEY,
    node_type               VARCHAR(256),
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_node_type;

CREATE TABLE IF NOT EXISTS ch_custom_biz_service (
    `id`              INTEGER NOT NULL PRIMARY KEY,
    `name`            VARCHAR(256),
    `uid`             CHAR(64),
    `icon_id`         INTEGER,
    `team_id`         INTEGER DEFAULT 1,
    `updated_at`      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_custom_biz_service;

CREATE TABLE IF NOT EXISTS ch_custom_biz_service_filter (
    `id`               INTEGER NOT NULL PRIMARY KEY,
    `client_filter`    TEXT,
    `server_filter`    TEXT,
    `updated_at`       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;
TRUNCATE TABLE ch_custom_biz_service_filter;

-- NPB/PCAP
CREATE TABLE IF NOT EXISTS acl (
    id                     INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    business_id            INTEGER NOT NULL,
    name                   CHAR(255),
    team_id                INTEGER DEFAULT 1,
    type                   INTEGER DEFAULT 2 COMMENT '1-epc; 2-custom',
    tap_type               INTEGER DEFAULT 3 COMMENT '1-WAN; 3-LAN',
    state                  INTEGER DEFAULT 1 COMMENT '0-disable; 1-enable',
    valid                  TINYINT(1) DEFAULT 1 COMMENT '0-invalid; 1-valid',
    invalid_description    TEXT,
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
  `team_id`                 INTEGER DEFAULT 1,
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
    team_id                INTEGER DEFAULT 1,
    resource_type          INTEGER NOT NULL COMMENT '1: epc, 2: vm, 3: pod_service, 4: pod_group, 5: vl2, 6: pod_cluster, 7: pod',
    resource_id            INTEGER NOT NULL,
    resource_sub_type      INTEGER,
    pod_namespace_id       INTEGER,
    resource_name          VARCHAR(256) NOT NULL
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE resource_group_extra_info;

CREATE TABLE IF NOT EXISTS group_acl (
    id                     INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    team_id                INTEGER DEFAULT 1,
    group_id               INTEGER NOT NULL,
    acl_id                 INTEGER NOT NULL,
    lcuuid                 CHAR(64)
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE group_acl;

CREATE TABLE IF NOT EXISTS policy_acl_group (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    team_id                 INTEGER DEFAULT 1,
    acl_ids                 TEXT NOT NULL COMMENT 'separated by ,',
    `count`                 INTEGER NOT NULL
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE policy_acl_group;

CREATE TABLE IF NOT EXISTS npb_tunnel (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id             INTEGER DEFAULT 1,
    team_id             INTEGER DEFAULT 1,
    name                CHAR(64) NOT NULL,
    ip                  CHAR(64),
    type                INTEGER COMMENT '(0-VXLAN；1-ERSPAN)',
    vni_input_type      TINYINT(1) DEFAULT 1 COMMENT '1. entire one 2. two parts',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    lcuuid              CHAR(64)
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE npb_tunnel;

CREATE TABLE IF NOT EXISTS npb_policy (
    id                     INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id                INTEGER DEFAULT 1,
    team_id                INTEGER DEFAULT 1,
    name                   CHAR(255),
    state                  INTEGER DEFAULT 1 COMMENT '0-disable; 1-enable',
    business_id            INTEGER NOT NULL,
    direction              TINYINT(1) DEFAULT 1 COMMENT '1-all; 2-forward; 3-backward;',
    vni                    INTEGER,
    npb_tunnel_id          INTEGER,
    distribute             TINYINT(1) DEFAULT 1 COMMENT '0-drop, 1-distribute',
    payload_slice          INTEGER DEFAULT NULL,
    acl_id                 INTEGER,
    policy_acl_group_id    INTEGER,
    vtap_type              TINYINT(1) COMMENT '1-vtap; 2-vtap_group',
    vtap_ids               TEXT COMMENT 'separated by ,',
    vtap_group_ids         TEXT COMMENT 'separated by ,',
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
    vtap_type              TINYINT(1) COMMENT '1-vtap; 2-vtap_group',
    vtap_ids               TEXT COMMENT 'separated by ,',
    vtap_group_ids         TEXT COMMENT 'separated by ,',
    payload_slice          INTEGER,
    policy_acl_group_id    INTEGER,
    user_id                INTEGER,
    created_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             TIMESTAMP NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    lcuuid                 CHAR(64),
    team_id                INTEGER DEFAULT 1
) ENGINE=innodb DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=1;
TRUNCATE TABLE pcap_policy;

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

-- Alerts/Reports
CREATE TABLE IF NOT EXISTS alarm_label (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    alarm_id                INTEGER NOT NULL,
    label_name              TEXT
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE alarm_label;

CREATE TABLE IF NOT EXISTS alarm_policy (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    team_id                 INTEGER DEFAULT 1,
    sub_view_id             INTEGER,
    sub_view_type           TINYINT(1) DEFAULT 0,
    sub_view_name           TEXT,
    sub_view_url            TEXT,
    sub_view_params         TEXT,
    sub_view_metrics        TEXT,
    sub_view_extra          TEXT,
    user_id                 INTEGER,
    name                    CHAR(128) NOT NULL,
    level                   TINYINT(1) NOT NULL COMMENT '0.low 1.middle 2.high',
    state                   TINYINT(1) DEFAULT 1 COMMENT '0.disabled 1.enabled',
    app_type                TINYINT NOT NULL COMMENT '1-system 3-indicator 4-custom_biz_service 5-comb',
    sub_type                TINYINT(1) DEFAULT 1 COMMENT '1-指标量;20-组件状态;21-组件性能;22-自动删除;23-资源状态;24-平台信息',
    deleted                 TINYINT(1) DEFAULT 0 COMMENT '0-not deleted; 1-deleted',
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at              DATETIME DEFAULT NULL,
    alert_time              BIGINT UNSIGNED DEFAULT 0,
    contrast_type           TINYINT(1) NOT NULL DEFAULT 1 COMMENT '1.abs 2.baseline',
    target_line_uid         TEXT,
    target_line_name        TEXT,
    target_field            TEXT,
    data_level              CHAR(64) NOT NULL DEFAULT "1m" COMMENT '1s or 1m',
    upper_threshold         DOUBLE,
    lower_threshold         DOUBLE,
    agg                     SMALLINT DEFAULT 0 COMMENT '0-聚合; 1-不聚合',
    delay                   SMALLINT DEFAULT 1 COMMENT '0-不延迟; 1-延迟',
    threshold_critical      TEXT,
    threshold_error         TEXT,
    threshold_warning       TEXT,
    trigger_nodata_event    TINYINT(1),
    query_url               TEXT,
    query_params            TEXT,
    query_conditions        TEXT,
    tag_conditions          TEXT,
    monitoring_frequency    CHAR(64) DEFAULT "1m",
    monitoring_interval     CHAR(64) DEFAULT "1m",
    trigger_info_event      INTEGER DEFAULT 0,
    trigger_recovery_event  INTEGER DEFAULT 1,
    recovery_event_levels   TEXT,
    lcuuid                  CHAR(64),
    biz_id                  INTEGER DEFAULT 0,
    biz_name                VARCHAR(256) DEFAULT '',
    auto_service_id_0       INTEGER DEFAULT 0,
    auto_service_type_0     INTEGER DEFAULT 0,
    auto_service_0          VARCHAR(256) DEFAULT '',
    auto_service_id_1       INTEGER DEFAULT 0,
    auto_service_type_1     INTEGER DEFAULT 0,
    auto_service_1          VARCHAR(256) DEFAULT '',
    comb_policy_lcuuids     TEXT
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE alarm_policy;

CREATE TABLE IF NOT EXISTS alarm_event (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    status                  CHAR(64),
    timestamp               DATETIME,
    end_time                BIGINT,
    policy_id               INTEGER,
    policy_name             TEXT,
    policy_level            INTEGER,
    policy_app_type         TINYINT,
    policy_sub_type         TINYINT,
    policy_contrast_type    TINYINT,
    policy_data_level       CHAR(64),
    policy_target_uid       TEXT,
    policy_target_name      TEXT,
    policy_go_to            TEXT,
    policy_target_field     TEXT,
    policy_endpoints        TEXT,
    sub_view_id             INTEGER,
    sub_view_name           TEXT,
    trigger_condition       TEXT,
    trigger_value           INTEGER,
    end_value               TEXT,
    value_unit              CHAR(64),
    endpoint_results        TEXT,
    event_level             INTEGER,
    lcuuid                  CHAR(64)
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE alarm_event;

CREATE TABLE IF NOT EXISTS report_policy (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                    CHAR(64) NOT NULL,
    view_id                 INTEGER NOT NULL,
    user_id                 INTEGER,
    `data_level`            enum('1s','1m') NOT NULL DEFAULT '1m',
    report_format           TINYINT(1) DEFAULT 1 COMMENT 'Type of format (1-html)',
    report_type             TINYINT(1) DEFAULT 1 COMMENT 'Type of reports (0-daily; 1-weekly; 2-monthly)',
    interval_time         enum('1d','1h') NOT NULL DEFAULT '1h',
    state                   TINYINT(1) DEFAULT 1 COMMENT '0-disable; 1-enable',
    push_type               TINYINT(1) DEFAULT 1 COMMENT '1-email',
    push_email              TEXT COMMENT 'separated by ,',
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    begin_at                TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lcuuid                  CHAR(64) NOT NULL
) ENGINE=innodb DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=1;
TRUNCATE TABLE report_policy;

CREATE TABLE IF NOT EXISTS `report` (
  `id`                     INTEGER NOT NULL AUTO_INCREMENT,
  `title`                  varchar(200) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '' COMMENT 'Title of the report',
  `begin_at`               datetime DEFAULT NULL COMMENT 'Start time of the report',
  `end_at`                 datetime DEFAULT NULL COMMENT 'End time of the report',
  `policy_id`              int(10) unsigned NOT NULL DEFAULT '0' COMMENT 'report_policy ID',
  `content`                LONGTEXT,
  `lcuuid`                 varchar(64) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '',
  `created_at`             datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  INDEX lcuuid(`lcuuid`),
  INDEX policy_id(`policy_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1 COMMENT='report records';

-- Prometheus
CREATE TABLE IF NOT EXISTS prometheus_metric_name (
    `id`            INT(10) NOT NULL PRIMARY KEY,
    `name`          VARCHAR(256) NOT NULL UNIQUE,
    `synced_at`     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8 COLLATE=utf8_bin;
TRUNCATE TABLE prometheus_metric_name;

CREATE TABLE IF NOT EXISTS prometheus_label_name (
    `id`            INT(10) NOT NULL PRIMARY KEY,
    `name`          VARCHAR(256) NOT NULL UNIQUE,
    `synced_at`     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8 COLLATE=utf8_bin;
TRUNCATE TABLE prometheus_label_name;

CREATE TABLE IF NOT EXISTS prometheus_label_value (
    `id`            INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `value`         TEXT,
    `synced_at`     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;
TRUNCATE TABLE prometheus_label_value;

CREATE TABLE IF NOT EXISTS prometheus_label (
    `id`            INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `name`          VARCHAR(256) NOT NULL,
    `value`         TEXT,
    `synced_at`     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;
TRUNCATE TABLE prometheus_label;

CREATE TABLE IF NOT EXISTS prometheus_metric_app_label_layout (
    `id`                        INT(10) NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `metric_name`               VARCHAR(256) NOT NULL,
    `app_label_name`            VARCHAR(256) NOT NULL,
    `app_label_column_index`    TINYINT(3) UNSIGNED NOT NULL,
    `synced_at`                 DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `created_at`                DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE INDEX metric_label_index(metric_name, app_label_name)
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;
TRUNCATE TABLE prometheus_metric_app_label_layout;

CREATE TABLE IF NOT EXISTS prometheus_metric_label_name (
    `id`                INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `metric_name`       VARCHAR(256) NOT NULL,
    `label_name_id`     INT NOT NULL,
    `synced_at`         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `created_at`        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE INDEX metric_label_name_index(metric_name, label_name_id)
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;
TRUNCATE TABLE prometheus_metric_label_name;

CREATE TABLE IF NOT EXISTS prometheus_metric_target (
    `id`            INT(10) NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `metric_name`   VARCHAR(256) NOT NULL,
    `target_id`     INT(10) NOT NULL,
    `synced_at`     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE INDEX metric_target_index(metric_name, target_id)
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;
TRUNCATE TABLE prometheus_metric_target;

CREATE TABLE IF NOT EXISTS `resource_version` (
    `id`            INT(11) NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `name`          VARCHAR(255) NOT NULL UNIQUE,
    `version`       INTEGER NOT NULL DEFAULT 0,
    `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;
TRUNCATE TABLE resource_version;

-- Business
CREATE TABLE IF NOT EXISTS biz_decode_dictionary (
    id                     INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    team_id                INTEGER DEFAULT 1,
    name                   VARCHAR(256) NOT NULL,
    yaml                   TEXT,
    created_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;
TRUNCATE TABLE biz_decode_dictionary;

CREATE TABLE IF NOT EXISTS biz_decode_policy (
    id                     INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    team_id                INTEGER DEFAULT 1,
    name                   VARCHAR(256) NOT NULL,
    yaml                   TEXT,
    created_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;
TRUNCATE TABLE biz_decode_policy;

CREATE TABLE IF NOT EXISTS biz_decode_policy_field (
    id                     INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    policy_id              INTEGER NOT NULL,
    name                   VARCHAR(256) NOT NULL,
    yaml                   TEXT,
    created_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;
TRUNCATE TABLE biz_decode_policy_field;

CREATE TABLE IF NOT EXISTS biz_decode_dictionary_policy_field_connection (
    id                     INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    dictionary_id          INTEGER NOT NULL,
    policy_field_id        INTEGER NOT NULL,
    policy_field_node_path VARCHAR(512) NOT NULL,
    created_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;
TRUNCATE TABLE biz_decode_dictionary_policy_field_connection;

CREATE TABLE IF NOT EXISTS biz_decode_policy_agent_group_connection (
    id                     INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    policy_id              INTEGER NOT NULL,
    agent_group_id         INTEGER NOT NULL,
    created_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;
TRUNCATE TABLE biz_decode_policy_agent_group_connection;
