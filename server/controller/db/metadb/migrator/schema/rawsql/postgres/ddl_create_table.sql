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
-- ============================================================================

-- System
-- Controllers
CREATE TABLE IF NOT EXISTS controller (
    id                  SERIAL PRIMARY KEY,
    state               INTEGER,
    name                VARCHAR(64),
    description         VARCHAR(256),
    ip                  VARCHAR(64),
    nat_ip              VARCHAR(64),
    cpu_num             INTEGER DEFAULT 0,
    memory_size         BIGINT DEFAULT 0,
    arch                VARCHAR(256),
    os                  VARCHAR(256),
    kernel_version      VARCHAR(256),
    vtap_max            INTEGER DEFAULT 2000,
    synced_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    nat_ip_enabled      SMALLINT DEFAULT 0,
    node_type           INTEGER DEFAULT 2,
    region_domain_prefix VARCHAR(256) DEFAULT '',
    node_name           VARCHAR(64),
    pod_ip              VARCHAR(64),
    pod_name            VARCHAR(64),
    ca_md5              VARCHAR(64),
    lcuuid              VARCHAR(64)
);
TRUNCATE TABLE controller;
COMMENT ON COLUMN controller.state IS '0.Temp 1.Creating 2.Complete 3.Modifying 4.Exception';
COMMENT ON COLUMN controller.cpu_num IS 'logical number of cpu';
COMMENT ON COLUMN controller.nat_ip_enabled IS '0: disabled 1:enabled';
COMMENT ON COLUMN controller.node_type IS 'region node type 1.master 2.slave';

CREATE TABLE IF NOT EXISTS az_controller_connection (
    id                      SERIAL PRIMARY KEY,
    az                      VARCHAR(64) DEFAULT 'ALL',
    region                  VARCHAR(64) DEFAULT 'ffffffff-ffff-ffff-ffff-ffffffffffff',
    controller_ip           VARCHAR(64),
    lcuuid                  VARCHAR(64)
);
TRUNCATE TABLE az_controller_connection;

-- Agents
CREATE TABLE IF NOT EXISTS vtap_group (
    id                      SERIAL PRIMARY KEY,
    team_id                 INTEGER DEFAULT 1,
    user_id                 INTEGER DEFAULT 1,
    name                    VARCHAR(64) NOT NULL,
    created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lcuuid                  VARCHAR(64),
    license_functions       VARCHAR(64),
    short_uuid              VARCHAR(32)
);
TRUNCATE TABLE vtap_group;

CREATE TABLE IF NOT EXISTS vtap_repo (
    id                  SERIAL PRIMARY KEY,
    name                VARCHAR(512),
    arch                VARCHAR(256) DEFAULT '',
    os                  VARCHAR(256) DEFAULT '',
    branch              VARCHAR(256) DEFAULT '',
    rev_count           VARCHAR(256) DEFAULT '',
    commit_id           VARCHAR(256) DEFAULT '',
    image               BYTEA,
    k8s_image           VARCHAR(512) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMP NOT NULL DEFAULT NOW()
);
TRUNCATE TABLE vtap_repo;

-- TODO to be removed
CREATE TABLE IF NOT EXISTS vtap_group_configuration(
    id                                      SERIAL PRIMARY KEY,
    user_id                                 INTEGER        DEFAULT 1,
    team_id                                 INTEGER        DEFAULT 1,
    max_collect_pps                         INTEGER,
    max_npb_bps                             BIGINT,
    max_cpus                                INTEGER,
    max_millicpus                           INTEGER,
    max_memory                              INTEGER,
    platform_sync_interval                  INTEGER,
    sync_interval                           INTEGER,
    stats_interval                          INTEGER,
    rsyslog_enabled                         SMALLINT       CHECK (rsyslog_enabled IN (0, 1)),
    system_load_circuit_breaker_threshold   NUMERIC(8,2),
    system_load_circuit_breaker_recover     NUMERIC(8,2),
    system_load_circuit_breaker_metric      VARCHAR(64),
    max_tx_bandwidth                        BIGINT,
    bandwidth_probe_interval                INTEGER,
    tap_interface_regex                     TEXT,
    max_escape_seconds                      INTEGER,
    mtu                                     INTEGER,
    output_vlan                             INTEGER,
    collector_socket_type                   VARCHAR(64),
    compressor_socket_type                  VARCHAR(64),
    npb_socket_type                         VARCHAR(64),
    npb_vlan_mode                           INTEGER,
    collector_enabled                       SMALLINT       CHECK (collector_enabled IN (0, 1)),
    vtap_flow_1s_enabled                    SMALLINT       CHECK (vtap_flow_1s_enabled IN (0, 1)),
    l4_log_tap_types                        TEXT,
    npb_dedup_enabled                       SMALLINT       CHECK (npb_dedup_enabled IN (0, 1)),
    platform_enabled                        SMALLINT       CHECK (platform_enabled IN (0, 1)),
    if_mac_source                           INTEGER,
    vm_xml_path                             TEXT,
    extra_netns_regex                       TEXT,
    nat_ip_enabled                          SMALLINT       CHECK (nat_ip_enabled IN (0, 1)),
    capture_packet_size                     INTEGER,
    inactive_server_port_enabled            SMALLINT       CHECK (inactive_server_port_enabled IN (0, 1)),
    inactive_ip_enabled                     SMALLINT       CHECK (inactive_ip_enabled IN (0, 1)),
    vtap_group_lcuuid                       VARCHAR(64),
    log_threshold                           INTEGER,
    log_level                               VARCHAR(64),
    log_retention                           INTEGER,
    http_log_proxy_client                   VARCHAR(64),
    http_log_trace_id                       TEXT,
    l7_log_packet_size                      INTEGER,
    l4_log_collect_nps_threshold            INTEGER,
    l7_log_collect_nps_threshold            INTEGER,
    l7_metrics_enabled                      SMALLINT       CHECK (l7_metrics_enabled IN (0, 1)),
    l7_log_store_tap_types                  TEXT,
    l4_log_ignore_tap_sides                 TEXT,
    l7_log_ignore_tap_sides                 TEXT,
    decap_type                              TEXT,
    capture_socket_type                     INTEGER,
    capture_bpf                             VARCHAR(512),
    tap_mode                                INTEGER,
    thread_threshold                        INTEGER,
    process_threshold                       INTEGER,
    ntp_enabled                             SMALLINT       CHECK (ntp_enabled IN (0, 1)),
    l4_performance_enabled                  SMALLINT       CHECK (l4_performance_enabled IN (0, 1)),
    pod_cluster_internal_ip                 SMALLINT       CHECK (pod_cluster_internal_ip IN (0, 1)),
    domains                                 TEXT,
    http_log_span_id                        TEXT,
    http_log_x_request_id                   VARCHAR(64),
    sys_free_memory_metric                  VARCHAR(64),
    sys_free_memory_limit                   INTEGER,
    log_file_size                           INTEGER,
    external_agent_http_proxy_enabled       SMALLINT       CHECK (external_agent_http_proxy_enabled IN (0, 1)),
    external_agent_http_proxy_port          INTEGER,
    proxy_controller_port                   INTEGER,
    analyzer_port                           INTEGER,
    proxy_controller_ip                     VARCHAR(128),
    analyzer_ip                             VARCHAR(128),
    wasm_plugins                            TEXT,
    so_plugins                              TEXT,
    yaml_config                             TEXT,
    lcuuid                                  VARCHAR(64)
);
TRUNCATE TABLE vtap_group_configuration;

CREATE TABLE IF NOT EXISTS agent_group_configuration (
    id                  SERIAL PRIMARY KEY,
    lcuuid              VARCHAR(64) NOT NULL,
    agent_group_lcuuid  VARCHAR(64) NOT NULL,
    yaml                TEXT,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE agent_group_configuration;
COMMENT ON COLUMN agent_group_configuration.created_at IS 'Timestamp when the record was created';
COMMENT ON COLUMN agent_group_configuration.updated_at IS 'Timestamp when the record was last updated';

CREATE TABLE IF NOT EXISTS agent_group_configuration_changelog (
    id                              SERIAL PRIMARY KEY,
    agent_group_configuration_id    INTEGER NOT NULL,
    user_id                         INTEGER NOT NULL,
    remarks                         TEXT,
    yaml_diff                       TEXT,
    lcuuid                          VARCHAR(64) NOT NULL,
    created_at                      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE agent_group_configuration_changelog;

CREATE TABLE IF NOT EXISTS vtap (
    id                      SERIAL PRIMARY KEY,
    name                    VARCHAR(256) NOT NULL,
    raw_hostname            VARCHAR(256),
    `owner`                 VARCHAR(64) DEFAULT '',
    state                   INTEGER DEFAULT 1,
    enable                  INTEGER DEFAULT 1,
    type                    INTEGER DEFAULT 0,
    ctrl_ip                 VARCHAR(64) NOT NULL,
    ctrl_mac                VARCHAR(64),
    tap_mac                 VARCHAR(64),
    analyzer_ip             VARCHAR(64) NOT NULL,
    cur_analyzer_ip         VARCHAR(64) NOT NULL,
    controller_ip           VARCHAR(64) NOT NULL,
    cur_controller_ip       VARCHAR(64) NOT NULL,
    launch_server           VARCHAR(64) NOT NULL,
    launch_server_id        INTEGER,
    az                      VARCHAR(64) DEFAULT '',
    region                  VARCHAR(64) DEFAULT '',
    revision                VARCHAR(256),
    synced_controller_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    synced_analyzer_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    boot_time               INTEGER DEFAULT 0,
    exceptions              BIGINT DEFAULT 0 CHECK (exceptions >= 0),
    vtap_lcuuid             VARCHAR(64) DEFAULT NULL,
    vtap_group_lcuuid       VARCHAR(64) DEFAULT NULL,
    cpu_num                 INTEGER DEFAULT 0,
    memory_size             BIGINT DEFAULT 0,
    grpc_buffer_size        BIGINT DEFAULT 0,
    arch                    VARCHAR(256),
    os                      VARCHAR(256),
    kernel_version          VARCHAR(256),
    process_name            VARCHAR(256),
    current_k8s_image       VARCHAR(512),
    license_type            INTEGER,
    license_functions       VARCHAR(64),
    enable_features         VARCHAR(64) DEFAULT NULL,
    disable_features        VARCHAR(64) DEFAULT NULL,
    follow_group_features   VARCHAR(64) DEFAULT NULL,
    tap_mode                INTEGER,
    team_id                 INTEGER,
    expected_revision       TEXT,
    upgrade_package         TEXT,
    lcuuid                  VARCHAR(64)
);
TRUNCATE TABLE vtap;
COMMENT ON COLUMN vtap.state IS '0.not-connected 1.normal';
COMMENT ON COLUMN vtap.enable IS '0: stop 1: running';
COMMENT ON COLUMN vtap.type IS '1: process 2: vm 3: public cloud 4: analyzer 5: physical machine 6: dedicated physical machine 7: host pod 8: vm pod';
COMMENT ON COLUMN vtap.cpu_num IS 'logical number of cpu';
COMMENT ON COLUMN vtap.license_type IS '1: A类 2: B类 3: C类';
COMMENT ON COLUMN vtap.license_functions IS 'separated by ,; 1: 流量分发 2: 网络监控 3: 应用监控';
COMMENT ON COLUMN vtap.enable_features IS 'separated by ,';
COMMENT ON COLUMN vtap.disable_features IS 'separated by ,';
COMMENT ON COLUMN vtap.follow_group_features IS 'separated by ,';

CREATE TABLE IF NOT EXISTS plugin (
    id                  SERIAL PRIMARY KEY,
    name                VARCHAR(256) NOT NULL,
    type                INTEGER NOT NULL,
    user_name           INTEGER NOT NULL DEFAULT 1,
    image               BYTEA NOT NULL,
    created_at          TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (name)
);
TRUNCATE TABLE plugin;
COMMENT ON COLUMN plugin.type IS '1: wasm 2: so 3: lua';
COMMENT ON COLUMN plugin.user_name IS '1: agent 2: server';

CREATE TABLE IF NOT EXISTS sys_configuration (
    id                  SERIAL PRIMARY KEY,
    param_name          VARCHAR(64) NOT NULL,
    value               VARCHAR(256),
    comments            TEXT,
    lcuuid              VARCHAR(64)
);
TRUNCATE TABLE sys_configuration;

-- Analyzers
CREATE TABLE IF NOT EXISTS analyzer (
    id                      SERIAL PRIMARY KEY,
    state                   INTEGER,
    ha_state                INTEGER DEFAULT 1,
    name                    VARCHAR(64),
    description             VARCHAR(256),
    ip                      VARCHAR(64),
    nat_ip                  VARCHAR(64),
    agg                     INTEGER DEFAULT 1,
    cpu_num                 INTEGER DEFAULT 0,
    memory_size             BIGINT DEFAULT 0,
    arch                    VARCHAR(256),
    os                      VARCHAR(256),
    kernel_version          VARCHAR(256),
    tsdb_shard_id           INTEGER,
    tsdb_replica_ip         VARCHAR(64),
    tsdb_data_mount_path    VARCHAR(256),
    pcap_data_mount_path    VARCHAR(256),
    vtap_max                INTEGER DEFAULT 200,
    synced_at               TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    nat_ip_enabled          SMALLINT DEFAULT 0,
    pod_ip                  VARCHAR(64),
    pod_name                VARCHAR(64),
    ca_md5                  VARCHAR(64),
    lcuuid                  VARCHAR(64)
);
TRUNCATE TABLE analyzer;
COMMENT ON COLUMN analyzer.state IS '0.Temp 1.Creating 2.Complete 3.Modifying 4.Exception';
COMMENT ON COLUMN analyzer.ha_state IS '1.master 2.backup';
COMMENT ON COLUMN analyzer.cpu_num IS 'logical number of cpu';
COMMENT ON COLUMN analyzer.nat_ip_enabled IS '0: disabled 1:enabled';

CREATE TABLE IF NOT EXISTS az_analyzer_connection (
    id                      SERIAL PRIMARY KEY,
    az                      VARCHAR(64) DEFAULT 'ALL',
    region                  VARCHAR(64) DEFAULT 'ffffffff-ffff-ffff-ffff-ffffffffffff',
    analyzer_ip             VARCHAR(64),
    lcuuid                  VARCHAR(64)
);
TRUNCATE TABLE az_analyzer_connection;

CREATE TABLE IF NOT EXISTS data_source (
    id                          SERIAL PRIMARY KEY,
    display_name                VARCHAR(64),
    data_table_collection       VARCHAR(64),
    state                       INTEGER DEFAULT 1,
    base_data_source_id         INTEGER,
    interval_time               INTEGER NOT NULL,
    retention_time              INTEGER NOT NULL,
    query_time                  INTEGER NOT NULL DEFAULT 0,
    summable_metrics_operator   VARCHAR(64),
    unsummable_metrics_operator VARCHAR(64),
    updated_at                  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    lcuuid                      VARCHAR(64)
);
TRUNCATE TABLE data_source;
COMMENT ON COLUMN data_source.state IS '0: Exception 1: Normal';
COMMENT ON COLUMN data_source.interval_time IS 'unit: s';
COMMENT ON COLUMN data_source.retention_time IS 'unit: hour';
COMMENT ON COLUMN data_source.query_time IS 'unit: minute';

-- Authorization
CREATE TABLE IF NOT EXISTS voucher (
    id                  SERIAL PRIMARY KEY,
    status              INTEGER DEFAULT 0,
    name                VARCHAR(256),
    value               BYTEA,
    lcuuid              VARCHAR(64)
);
TRUNCATE TABLE voucher;

CREATE TABLE IF NOT EXISTS license_func_log (
    id                      SERIAL PRIMARY KEY,
    team_id                 INTEGER DEFAULT 1,
    agent_id                INTEGER NOT NULL,
    agent_name              VARCHAR(256) NOT NULL,
    user_id                 INTEGER NOT NULL,
    license_function        INTEGER NOT NULL,
    enabled                 INTEGER NOT NULL,
    agent_group_name        VARCHAR(64),
    agent_group_operation   SMALLINT,
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE license_func_log;
COMMENT ON COLUMN license_func_log.license_function IS '1.traffic distribution 2.network monitoring 3.call monitoring 4.function monitoring 5.application monitoring 6.indicator monitoring 7.database monitoring 8.log monitoring 9.max';
COMMENT ON COLUMN license_func_log.enabled IS '0.false 1.true';
COMMENT ON COLUMN license_func_log.agent_group_operation IS '0.follow 1.update';

CREATE TABLE IF NOT EXISTS kubernetes_cluster (
    id                      SERIAL PRIMARY KEY,
    cluster_id              VARCHAR(256) NOT NULL,
    value                   VARCHAR(256) NOT NULL,
    updated_time            TIMESTAMP,
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    synced_at               TIMESTAMP,
    UNIQUE (cluster_id)
);
TRUNCATE TABLE kubernetes_cluster;

CREATE TABLE IF NOT EXISTS mail_server (
    id                      SERIAL PRIMARY KEY,
    status                  INTEGER NOT NULL,
    host                    TEXT NOT NULL,
    port                    INTEGER NOT NULL,
    user_name               TEXT NOT NULL,
    password                TEXT NOT NULL,
    security                TEXT NOT NULL,
    ntlm_enabled            INTEGER,
    ntlm_name               TEXT,
    ntlm_password           TEXT,
    lcuuid                  VARCHAR(64) DEFAULT ''
);
TRUNCATE TABLE mail_server;

CREATE TABLE IF NOT EXISTS dial_test_task (
    id                      SERIAL PRIMARY KEY,
    name                    VARCHAR(256) NOT NULL,
    protocol                INTEGER NOT NULL,
    host                    VARCHAR(256) NOT NULL,
    overtime_time           INTEGER DEFAULT 2000,
    payload                 INTEGER DEFAULT 64,
    ttl                     SMALLINT DEFAULT 64,
    dial_location           VARCHAR(256) NOT NULL,
    dial_frequency          INTEGER DEFAULT 1000,
    pcap                    BYTEA,
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE dial_test_task;
COMMENT ON COLUMN dial_test_task.protocol IS '1.ICMP';
COMMENT ON COLUMN dial_test_task.host IS 'dial test address';
COMMENT ON COLUMN dial_test_task.overtime_time IS 'unit: ms';
COMMENT ON COLUMN dial_test_task.dial_frequency IS 'unit: ms';

-- Assets
-- Clouds
CREATE TABLE IF NOT EXISTS resource_event (
    id                  SERIAL PRIMARY KEY,
    domain              VARCHAR(64) DEFAULT '',
    sub_domain          VARCHAR(64) DEFAULT '',
    resource_lcuuid     VARCHAR(64) DEFAULT '',
    content             TEXT,
    created_at          TIMESTAMP NOT NULL DEFAULT NOW()
);
TRUNCATE TABLE resource_event;


CREATE TABLE IF NOT EXISTS domain_additional_resource (
    id                  SERIAL PRIMARY KEY,
    domain              VARCHAR(64) DEFAULT '',
    content             TEXT,
    created_at          TIMESTAMP NOT NULL DEFAULT NOW(),
    compressed_content  BYTEA
);
TRUNCATE TABLE domain_additional_resource;

CREATE TABLE IF NOT EXISTS domain (
    id                  SERIAL PRIMARY KEY,
    team_id             INTEGER DEFAULT 1,
    user_id             INTEGER DEFAULT 1,
    name                VARCHAR(64),
    icon_id             INTEGER,
    display_name        VARCHAR(64) DEFAULT '',
    cluster_id          VARCHAR(64),
    ip                  VARCHAR(64),
    role                INTEGER DEFAULT 0,
    type                INTEGER DEFAULT 0,
    public_ip           VARCHAR(64) DEFAULT NULL,
    config              TEXT,
    error_msg           TEXT,
    enabled             INTEGER NOT NULL DEFAULT 1,
    state               INTEGER NOT NULL DEFAULT 1,
    exceptions          BIGINT DEFAULT 0 CHECK (exceptions >= 0 AND exceptions <= 4294967295),
    controller_ip       VARCHAR(64),
    lcuuid              VARCHAR(64) DEFAULT '',
    synced_at           TIMESTAMP DEFAULT NULL,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (lcuuid)
);
TRUNCATE TABLE domain;
COMMENT ON COLUMN domain.role IS '1.BSS 2.OSS 3.OpenStack 4.VSphere';
COMMENT ON COLUMN domain.type IS '1.openstack 2.vsphere 3.nsp 4.tencent 5.filereader 6.aws 8.zstack 9.aliyun 10.huawei prv 11.k8s 12.simulation 13.huawei 14.qingcloud 15.qingcloud_private 16.F5 17.CMB_CMDB 18.azure 19.apsara_stack 20.tencent_tce 21.qingcloud_k8s 22.kingsoft_private 23.genesis 24.microsoft_acs 25.baidu_bce';
COMMENT ON COLUMN domain.enabled IS '0.false 1.true';
COMMENT ON COLUMN domain.state IS '1.normal 2.deleting 3.exception 4.warning 5.no_license';

CREATE TABLE IF NOT EXISTS sub_domain (
    id                  SERIAL PRIMARY KEY,
    team_id             INTEGER DEFAULT 1,
    user_id             INTEGER DEFAULT 1,
    domain              VARCHAR(64) DEFAULT '',
    name                VARCHAR(64) DEFAULT '',
    display_name        VARCHAR(64) DEFAULT '',
    create_method       INTEGER DEFAULT 0,
    cluster_id          VARCHAR(64) DEFAULT '',
    config              TEXT,
    error_msg           TEXT,
    enabled             INTEGER NOT NULL DEFAULT 1,
    state               INTEGER NOT NULL DEFAULT 1,
    exceptions          BIGINT DEFAULT 0 CHECK (exceptions >= 0 AND exceptions <= 4294967295),
    lcuuid              VARCHAR(64) DEFAULT '',
    synced_at           TIMESTAMP DEFAULT NULL,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (lcuuid)
);
TRUNCATE TABLE sub_domain;
COMMENT ON COLUMN sub_domain.create_method IS '0.learning 1.user_defined';
COMMENT ON COLUMN sub_domain.enabled IS '0.false 1.true';
COMMENT ON COLUMN sub_domain.state IS '1.normal 2.deleting 3.exception 4.warning 5.no_license';

CREATE TABLE IF NOT EXISTS region (
    id                  SERIAL PRIMARY KEY,
    name                VARCHAR(64) DEFAULT '',
    create_method       INTEGER DEFAULT 0,
    label               VARCHAR(64) DEFAULT '',
    longitude           DOUBLE PRECISION,
    latitude            DOUBLE PRECISION,
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at          TIMESTAMP DEFAULT NULL,
    UNIQUE (lcuuid)
);
TRUNCATE TABLE region;
COMMENT ON COLUMN region.create_method IS '0.learning 1.user_defined';

CREATE TABLE IF NOT EXISTS az (
    id                  SERIAL PRIMARY KEY,
    name                VARCHAR(64) DEFAULT '',
    create_method       INTEGER DEFAULT 0,
    label               VARCHAR(64) DEFAULT '',
    region              VARCHAR(64) DEFAULT '',
    domain              VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at          TIMESTAMP DEFAULT NULL,
    UNIQUE (lcuuid)
);
TRUNCATE TABLE az;
COMMENT ON COLUMN az.create_method IS '0.learning 1.user_defined';

-- Computes
CREATE TABLE IF NOT EXISTS host_device (
    id                  SERIAL PRIMARY KEY,
    type                INTEGER,
    state               INTEGER,
    name                VARCHAR(256) DEFAULT '',
    alias               VARCHAR(64) DEFAULT '',
    description         VARCHAR(256) DEFAULT '',
    ip                  VARCHAR(64) DEFAULT '',
    hostname            VARCHAR(64) DEFAULT '',
    htype               INTEGER,
    create_method       INTEGER DEFAULT 0,
    user_name           VARCHAR(64) DEFAULT '',
    user_passwd         VARCHAR(64) DEFAULT '',
    vcpu_num            INTEGER DEFAULT 0,
    mem_total           INTEGER DEFAULT 0,
    rack                VARCHAR(64),
    rackid              INTEGER,
    topped              INTEGER DEFAULT 0,
    az                  VARCHAR(64) DEFAULT '',
    region              VARCHAR(64) DEFAULT '',
    domain              VARCHAR(64) DEFAULT '',
    extra_info          TEXT,
    lcuuid              VARCHAR(64) DEFAULT '',
    synced_at           TIMESTAMP NOT NULL DEFAULT NOW(),
    created_at          TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMP NOT NULL DEFAULT NOW(),
    deleted_at          TIMESTAMP DEFAULT NULL
);
TRUNCATE TABLE host_device;
COMMENT ON COLUMN host_device.type IS '1.Server 3.Gateway 4.DFI';
COMMENT ON COLUMN host_device.state IS '0.Temp 1.Creating 2.Complete 3.Modifying 4.Exception';
COMMENT ON COLUMN host_device.htype IS '1. Xen host 2. VMware host 3. KVM host 4. Public cloud host 5. Hyper-V';
COMMENT ON COLUMN host_device.create_method IS '0.learning 1.user_defined';
COMMENT ON COLUMN host_device.mem_total IS 'unit: M';

CREATE TABLE IF NOT EXISTS vm (
    id                  SERIAL PRIMARY KEY,
    state               INTEGER NOT NULL,
    name                VARCHAR(256) DEFAULT '',
    label               VARCHAR(64) DEFAULT '',
    ip                  VARCHAR(64) DEFAULT '',
    vl2id               INTEGER DEFAULT 0,
    hostname            VARCHAR(64) DEFAULT '',
    create_method       INTEGER DEFAULT 0,
    htype               INTEGER DEFAULT 1,
    launch_server       VARCHAR(64) DEFAULT '',
    host_id             INTEGER DEFAULT 0,
    learned_cloud_tags  TEXT,
    custom_cloud_tags   TEXT,
    epc_id              INTEGER DEFAULT 0,
    domain              VARCHAR(64) DEFAULT '',
    az                  VARCHAR(64) DEFAULT '',
    region              VARCHAR(64) DEFAULT '',
    userid              INTEGER,
    uid                 VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at          TIMESTAMP DEFAULT NULL
);
TRUNCATE TABLE vm;
CREATE INDEX vm_state_server_index ON vm (state, launch_server);
CREATE INDEX vm_launch_server_index ON vm (launch_server);
CREATE INDEX vm_epc_id_index ON vm (epc_id);
CREATE INDEX vm_az_index ON vm (az);
CREATE INDEX vm_region_index ON vm (region);
COMMENT ON COLUMN vm.state IS '0.Temp 1.Creating 2.Created 3.To run 4.Running 5.To suspend 6.Suspended 7.To resume 8.To stop 9.Stopped 10.Modifing 11.Exception 12.Destroying';
COMMENT ON COLUMN vm.create_method IS '0.learning 1.user_defined';
COMMENT ON COLUMN vm.htype IS '1.vm-c 2.bm-c 3.vm-n 4.bm-n 5.vm-s 6.bm-s';
COMMENT ON COLUMN vm.cloud_tags IS 'separated by ,';

-- Networks
CREATE TABLE IF NOT EXISTS epc (
    id                  SERIAL PRIMARY KEY,
    userid              INTEGER DEFAULT 0,
    name                VARCHAR(256) DEFAULT '',
    create_method       INTEGER DEFAULT 0,
    label               VARCHAR(64) DEFAULT '',
    `owner`             VARCHAR(64) DEFAULT '',
    alias               VARCHAR(64) DEFAULT '',
    domain              VARCHAR(64) DEFAULT '',
    region              VARCHAR(64) DEFAULT '',
    az                  VARCHAR(64) DEFAULT '',
    order_id            INTEGER DEFAULT 0,
    tunnel_id           INTEGER DEFAULT 0,
    operationid         INTEGER DEFAULT 0,
    mode                INTEGER DEFAULT 2,
    topped              INTEGER DEFAULT 0,
    cidr                VARCHAR(64) DEFAULT '',
    uid                 VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at          TIMESTAMP DEFAULT NULL,
    UNIQUE (lcuuid)
);
TRUNCATE TABLE epc;
CREATE INDEX epc_region_index ON epc (region);
COMMENT ON COLUMN epc.create_method IS '0.learning 1.user_defined';
COMMENT ON COLUMN epc.mode IS '1:route, 2:transparent';

CREATE TABLE IF NOT EXISTS vl2 (
    id                  SERIAL PRIMARY KEY,
    state               INTEGER NOT NULL,
    net_type            INTEGER DEFAULT 4,
    name                VARCHAR(256) NOT NULL,
    create_method       INTEGER DEFAULT 0,
    label               VARCHAR(64) DEFAULT '',
    alias               VARCHAR(64) DEFAULT '',
    description         VARCHAR(256) DEFAULT '',
    sub_domain          VARCHAR(64) DEFAULT '',
    domain              VARCHAR(64) DEFAULT '',
    region              VARCHAR(64) DEFAULT '',
    az                  VARCHAR(64) DEFAULT '',
    isp                 INTEGER DEFAULT 0,
    userid              INTEGER DEFAULT 0,
    epc_id              INTEGER DEFAULT 0,
    segmentation_id     INTEGER DEFAULT 0,
    tunnel_id           INTEGER DEFAULT 0,
    shared              BOOLEAN DEFAULT FALSE,
    topped              INTEGER DEFAULT 0,
    is_vip              INTEGER DEFAULT 0,
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at          TIMESTAMP DEFAULT NULL,
    UNIQUE (lcuuid)
);
TRUNCATE TABLE vl2;
CREATE INDEX vl2_region_index ON vl2 (region);
COMMENT ON COLUMN vl2.state IS '0.Temp 1.Creating 2.Created 3.Exception 4.Modifing 5.Destroying 6.Destroyed';
COMMENT ON COLUMN vl2.net_type IS '1.CTRL 2.SERVICE 3.WAN 4.LAN';
COMMENT ON COLUMN vl2.create_method IS '0.learning 1.user_defined';

CREATE TABLE IF NOT EXISTS vl2_net (
    id                  SERIAL PRIMARY KEY,
    prefix              VARCHAR(64) DEFAULT '',
    netmask             VARCHAR(64) DEFAULT '',
    vl2id               INTEGER DEFAULT 0,
    net_index           INTEGER DEFAULT 0,
    name                VARCHAR(256) DEFAULT '',
    label               VARCHAR(64) DEFAULT '',
    sub_domain          VARCHAR(64) DEFAULT '',
    domain              VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE vl2_net;

CREATE TABLE IF NOT EXISTS vnet (
    id                  SERIAL PRIMARY KEY,
    state               INTEGER NOT NULL,
    name                VARCHAR(256) DEFAULT '',
    label               VARCHAR(64) DEFAULT '',
    description         VARCHAR(256) DEFAULT '',
    epc_id              INTEGER DEFAULT 0,
    gw_launch_server    VARCHAR(64) DEFAULT '',
    domain              VARCHAR(64) DEFAULT '',
    region              VARCHAR(64) DEFAULT '',
    az                  VARCHAR(64) DEFAULT '',
    userid              INTEGER,
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at          TIMESTAMP DEFAULT NULL
);
TRUNCATE TABLE vnet;
CREATE INDEX vnet_state_server_index ON vnet (state, gw_launch_server);
COMMENT ON COLUMN vnet.state IS '0.Temp 1.Creating 2.Created 3.Exception 4.Modifing 5.Destroying 6.To run 7.Running 8.To stop 9.Stopped';

CREATE TABLE IF NOT EXISTS routing_table (
    id                  SERIAL PRIMARY KEY,
    vnet_id             INTEGER,
    destination         TEXT,
    nexthop_type        TEXT,
    nexthop             TEXT,
    domain              VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64),
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE routing_table;
CREATE INDEX vnet_id_index ON routing_table (vnet_id);

CREATE TABLE IF NOT EXISTS dhcp_port (
    id                  SERIAL PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    domain              VARCHAR(64) DEFAULT '',
    region              VARCHAR(64) DEFAULT '',
    az                  VARCHAR(64) DEFAULT '',
    userid              INTEGER DEFAULT 0,
    epc_id              INTEGER DEFAULT 0,
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at          TIMESTAMP DEFAULT NULL
);
TRUNCATE TABLE dhcp_port;

CREATE TABLE IF NOT EXISTS vinterface (
    id                  SERIAL PRIMARY KEY,
    name                VARCHAR(64) DEFAULT '',
    ifindex             INTEGER NOT NULL,
    state               INTEGER NOT NULL,
    create_method       INTEGER DEFAULT 0,
    iftype              INTEGER DEFAULT 0,
    mac                 VARCHAR(32) DEFAULT '',
    vmac                VARCHAR(32) DEFAULT '',
    tap_mac             VARCHAR(32) DEFAULT '',
    subnetid            INTEGER DEFAULT 0,
    vlantag             INTEGER DEFAULT 0,
    devicetype          INTEGER,
    deviceid            INTEGER,
    netns_id            BIGINT DEFAULT 0 CHECK (netns_id >= 0 AND netns_id <= 4294967295),
    vtap_id             INTEGER DEFAULT 0,
    epc_id              INTEGER DEFAULT 0,
    sub_domain          VARCHAR(64) DEFAULT '',
    domain              VARCHAR(64) DEFAULT '',
    region              VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE vinterface;
CREATE INDEX vinterface_epc_id_index ON vinterface (epc_id);
COMMENT ON COLUMN vinterface.state IS '1. Attached 2.Detached 3.Exception';
COMMENT ON COLUMN vinterface.create_method IS '0.learning 1.user_defined';
COMMENT ON COLUMN vinterface.iftype IS '0.Unknown 1.Control 2.Service 3.WAN 4.LAN 5.Trunk 6.Tap 7.Tool';
COMMENT ON COLUMN vinterface.devicetype IS 'Type 0.unknown 1.vm 2.vgw 3.third-party-device 4.vmwaf 5.NSP-vgateway 6.host-device 7.network-device 9.DHCP-port 10.pod 11.pod_service 12. redis_instance 13. rds_instance 14. pod_node 15. load_balance 16. nat_gateway';
COMMENT ON COLUMN vinterface.deviceid IS 'unknown: Senseless ID, vm: vm ID, vgw/NSP-vgateway: vnet ID, third-party-device: third_party_device ID, vmwaf: vmwaf ID, host-device: host_device ID, network-device: network_device ID';

CREATE TABLE IF NOT EXISTS vinterface_ip (
    id                  SERIAL PRIMARY KEY,
    ip                  VARCHAR(64) DEFAULT '',
    netmask             VARCHAR(64) DEFAULT '',
    gateway             VARCHAR(64) DEFAULT '',
    create_method       INTEGER DEFAULT 0,
    vl2id               INTEGER DEFAULT 0,
    vl2_net_id          INTEGER DEFAULT 0,
    net_index           INTEGER DEFAULT 0,
    sub_domain          VARCHAR(64) DEFAULT '',
    domain              VARCHAR(64) DEFAULT '',
    vifid               INTEGER DEFAULT 0,
    isp                 INTEGER DEFAULT 0,
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE vinterface_ip;
CREATE INDEX vinterface_ip_ip_index ON vinterface_ip (ip);
CREATE INDEX vinterface_ip_vifid_index ON vinterface_ip (vifid);
COMMENT ON COLUMN vinterface_ip.create_method IS '0.learning 1.user_defined';
COMMENT ON COLUMN vinterface_ip.isp IS 'Used for multi-ISP access';

CREATE TABLE IF NOT EXISTS ip_resource (
    id                  SERIAL PRIMARY KEY,
    ip                  VARCHAR(64) DEFAULT '',
    alias               VARCHAR(64) DEFAULT '',
    netmask             INTEGER,
    gateway             VARCHAR(64) DEFAULT '',
    create_method       INTEGER DEFAULT 0,
    userid              INTEGER DEFAULT 0,
    isp                 INTEGER,
    vifid               INTEGER DEFAULT 0,
    vl2_net_id          INTEGER DEFAULT 0,
    sub_domain          VARCHAR(64) DEFAULT '',
    domain              VARCHAR(64) DEFAULT '',
    region              VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ip_resource;
CREATE INDEX ip_resource_ip_index ON ip_resource (ip);
CREATE INDEX ip_resource_vifid_index ON ip_resource (vifid);
COMMENT ON COLUMN ip_resource.create_method IS '0.learning 1.user_defined';

CREATE TABLE IF NOT EXISTS floatingip (
    id                  SERIAL PRIMARY KEY,
    domain              VARCHAR(64) DEFAULT '',
    region              VARCHAR(64) DEFAULT '',
    epc_id              INTEGER DEFAULT 0,
    vl2_id              INTEGER,
    vm_id               INTEGER,
    ip                  VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE floatingip;

CREATE TABLE IF NOT EXISTS vip (
    id                  SERIAL PRIMARY KEY,
    lcuuid              VARCHAR(64),
    ip                  VARCHAR(64),
    domain              VARCHAR(64) DEFAULT '',
    vtap_id             INTEGER,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE vip;

-- Network Services
CREATE TABLE IF NOT EXISTS nat_gateway (
    id                  SERIAL PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    label               VARCHAR(64) DEFAULT '',
    floating_ips        TEXT,
    epc_id              INTEGER DEFAULT 0,
    az                  VARCHAR(64) DEFAULT '',
    region              VARCHAR(64) DEFAULT '',
    domain              VARCHAR(64) DEFAULT '',
    uid                 VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at          TIMESTAMP DEFAULT NULL
);
TRUNCATE TABLE nat_gateway;
COMMENT ON COLUMN nat_gateway.floating_ips IS 'separated by ,';

CREATE TABLE IF NOT EXISTS nat_rule (
    id                  SERIAL PRIMARY KEY,
    nat_id              INTEGER DEFAULT 0,
    type                VARCHAR(16) DEFAULT '',
    protocol            VARCHAR(64) DEFAULT '',
    floating_ip         VARCHAR(64) DEFAULT '',
    floating_ip_port    INTEGER DEFAULT NULL,
    fixed_ip            VARCHAR(64) DEFAULT '',
    fixed_ip_port       INTEGER DEFAULT NULL,
    port_id             INTEGER DEFAULT NULL,
    domain              VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE nat_rule;
CREATE INDEX nat_rule_nat_id_index ON nat_rule (nat_id);

CREATE TABLE IF NOT EXISTS nat_vm_connection (
    id                  SERIAL PRIMARY KEY,
    nat_id              INTEGER,
    vm_id               INTEGER,
    domain              VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE nat_vm_connection;

CREATE TABLE IF NOT EXISTS lb (
    id                  SERIAL PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    label               VARCHAR(64) DEFAULT '',
    model               INTEGER DEFAULT 0,
    vip                 TEXT,
    epc_id              INTEGER DEFAULT 0,
    az                  VARCHAR(64) DEFAULT '',
    region              VARCHAR(64) DEFAULT '',
    domain              VARCHAR(64) DEFAULT '',
    uid                 VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at          TIMESTAMP DEFAULT NULL
);
TRUNCATE TABLE lb;
COMMENT ON COLUMN lb.model IS '1.Internal 2.External';
COMMENT ON COLUMN lb.vip IS 'separated by ,';

CREATE TABLE IF NOT EXISTS lb_listener (
    id                  SERIAL PRIMARY KEY,
    lb_id               INTEGER DEFAULT 0,
    name                VARCHAR(256) DEFAULT '',
    ips                 TEXT,
    snat_ips            TEXT,
    label               VARCHAR(64) DEFAULT '',
    port                INTEGER DEFAULT NULL,
    protocol            VARCHAR(64) DEFAULT '',
    domain              VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at          TIMESTAMP DEFAULT NULL
);
TRUNCATE TABLE lb_listener;
CREATE INDEX lb_listener_lb_id_index ON lb_listener (lb_id);
COMMENT ON COLUMN lb_listener.ips IS 'separated by ,';
COMMENT ON COLUMN lb_listener.snat_ips IS 'separated by ,';

CREATE TABLE IF NOT EXISTS lb_target_server (
    id                  SERIAL PRIMARY KEY,
    lb_id               INTEGER DEFAULT 0,
    lb_listener_id      INTEGER DEFAULT 0,
    epc_id              INTEGER DEFAULT 0,
    type                INTEGER DEFAULT 0,
    ip                  VARCHAR(64) DEFAULT '',
    vm_id               INTEGER DEFAULT 0,
    port                INTEGER DEFAULT NULL,
    protocol            VARCHAR(64) DEFAULT '',
    domain              VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE lb_target_server;
CREATE INDEX lb_target_server_lb_id_index ON lb_target_server (lb_id);
COMMENT ON COLUMN lb_target_server.type IS '1.VM 2.IP';

CREATE TABLE IF NOT EXISTS lb_vm_connection (
    id                  SERIAL PRIMARY KEY,
    lb_id               INTEGER,
    vm_id               INTEGER,
    domain              VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE lb_vm_connection;

CREATE TABLE IF NOT EXISTS peer_connection (
    id                  SERIAL PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    label               VARCHAR(64) DEFAULT '',
    team_id             INTEGER NOT NULL,
    local_epc_id        INTEGER DEFAULT NULL,
    remote_epc_id       INTEGER DEFAULT NULL,
    local_domain        VARCHAR(64) NOT NULL,
    remote_domain       VARCHAR(64) NOT NULL,
    create_method       INTEGER DEFAULT 0,
    domain              VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at          TIMESTAMP DEFAULT NULL
);
TRUNCATE TABLE peer_connection;
COMMENT ON COLUMN peer_connection.create_method IS '0.learning 1.user_defined';

CREATE TABLE IF NOT EXISTS cen (
    id                  SERIAL PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    label               VARCHAR(64) DEFAULT '',
    alias               VARCHAR(64) DEFAULT '',
    epc_ids             TEXT,
    domain              VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at          TIMESTAMP DEFAULT NULL
);
TRUNCATE TABLE cen;
COMMENT ON COLUMN cen.epc_ids IS 'separated by ,';

-- Storage Services
CREATE TABLE IF NOT EXISTS redis_instance (
    id                  SERIAL PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    label               VARCHAR(64) DEFAULT '',
    state               SMALLINT NOT NULL DEFAULT 0,
    domain              VARCHAR(64) DEFAULT '',
    region              VARCHAR(64) DEFAULT '',
    az                  VARCHAR(64) DEFAULT '',
    epc_id              INTEGER DEFAULT 0,
    version             VARCHAR(64) DEFAULT '',
    internal_host       VARCHAR(128) DEFAULT '',
    public_host         VARCHAR(128) DEFAULT '',
    uid                 VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at          TIMESTAMP DEFAULT NULL
);
TRUNCATE TABLE redis_instance;
COMMENT ON COLUMN redis_instance.state IS '0. Unknown 1. Running 2. Recovering';

CREATE TABLE IF NOT EXISTS rds_instance (
    id                  SERIAL PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    label               VARCHAR(64) DEFAULT '',
    state               SMALLINT NOT NULL DEFAULT 0,
    domain              VARCHAR(64) DEFAULT '',
    region              VARCHAR(64) DEFAULT '',
    az                  VARCHAR(64) DEFAULT '',
    epc_id              INTEGER DEFAULT 0,
    type                INTEGER DEFAULT 0,
    version             VARCHAR(64) DEFAULT '',
    series              SMALLINT NOT NULL DEFAULT 0,
    model               SMALLINT NOT NULL DEFAULT 0,
    uid                 VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at          TIMESTAMP DEFAULT NULL
);
TRUNCATE TABLE rds_instance;
COMMENT ON COLUMN rds_instance.state IS '0. Unknown 1. Running 2. Recovering';
COMMENT ON COLUMN rds_instance.type IS '0. Unknown 1. MySQL 2. SqlServer 3. PPAS 4. PostgreSQL 5. MariaDB';
COMMENT ON COLUMN rds_instance.series IS '0. Unknown 1. basic 2. HA';
COMMENT ON COLUMN rds_instance.model IS '0. Unknown 1. Primary 2. Readonly 3. Temporary 4. Disaster recovery 5. share';

-- Kubernetes
CREATE TABLE IF NOT EXISTS pod_cluster (
    id                  SERIAL PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    cluster_name        VARCHAR(256) DEFAULT '',
    version             VARCHAR(256) DEFAULT '',
    epc_id              INTEGER,
    az                  VARCHAR(64) DEFAULT '',
    region              VARCHAR(64) DEFAULT '',
    sub_domain          VARCHAR(64) DEFAULT '',
    domain              VARCHAR(64) DEFAULT '',
    uid                 VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at          TIMESTAMP DEFAULT NULL
);
TRUNCATE TABLE pod_cluster;

CREATE TABLE IF NOT EXISTS pod_node (
    id                  SERIAL PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    alias               VARCHAR(64) DEFAULT '',
    type                INTEGER DEFAULT NULL,
    server_type         INTEGER DEFAULT NULL,
    state               INTEGER DEFAULT 1,
    ip                  VARCHAR(64) DEFAULT '',
    hostname            VARCHAR(64) DEFAULT '',
    vcpu_num            INTEGER DEFAULT 0,
    mem_total           INTEGER DEFAULT 0,
    pod_cluster_id      INTEGER,
    region              VARCHAR(64) DEFAULT '',
    az                  VARCHAR(64) DEFAULT '',
    epc_id              INTEGER DEFAULT NULL,
    sub_domain          VARCHAR(64) DEFAULT '',
    domain              VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at          TIMESTAMP DEFAULT NULL
);
TRUNCATE TABLE pod_node;
CREATE INDEX pod_node_pod_cluster_id_index ON pod_node (pod_cluster_id);
CREATE INDEX pod_node_epc_id_index ON pod_node (epc_id);
CREATE INDEX pod_node_az_index ON pod_node (az);
CREATE INDEX pod_node_region_index ON pod_node (region);
COMMENT ON COLUMN pod_node.type IS '1: Master 2: Node';
COMMENT ON COLUMN pod_node.server_type IS '1: Host 2: VM';
COMMENT ON COLUMN pod_node.state IS '0: Exception 1: Normal';
COMMENT ON COLUMN pod_node.mem_total IS 'unit: M';

CREATE TABLE IF NOT EXISTS vm_pod_node_connection (
    id                  SERIAL PRIMARY KEY,
    vm_id               INTEGER,
    pod_node_id         INTEGER,
    domain              VARCHAR(64) DEFAULT '',
    sub_domain          VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE vm_pod_node_connection;

CREATE TABLE IF NOT EXISTS pod_namespace (
    id                  SERIAL PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    learned_cloud_tags  TEXT,
    custom_cloud_tags   TEXT,
    pod_cluster_id      INTEGER DEFAULT NULL,
    az                  VARCHAR(64) DEFAULT '',
    region              VARCHAR(64) DEFAULT '',
    sub_domain          VARCHAR(64) DEFAULT '',
    domain              VARCHAR(64) DEFAULT '',
    uid                 VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at          TIMESTAMP DEFAULT NULL
);
TRUNCATE TABLE pod_namespace;

CREATE TABLE IF NOT EXISTS pod_ingress (
    id                  SERIAL PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    alias               VARCHAR(64) DEFAULT '',
    pod_namespace_id    INTEGER DEFAULT NULL,
    pod_cluster_id      INTEGER DEFAULT NULL,
    az                  VARCHAR(64) DEFAULT '',
    region              VARCHAR(64) DEFAULT '',
    sub_domain          VARCHAR(64) DEFAULT '',
    domain              VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at          TIMESTAMP DEFAULT NULL
);
TRUNCATE TABLE pod_ingress;

CREATE TABLE IF NOT EXISTS pod_ingress_rule (
    id                  SERIAL PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    protocol            VARCHAR(64) DEFAULT '',
    host                TEXT,
    pod_ingress_id      INTEGER DEFAULT NULL,
    sub_domain          VARCHAR(64) DEFAULT '',
    domain              VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE pod_ingress_rule;
CREATE INDEX pod_ingress_rule_pod_ingress_id_index ON pod_ingress_rule (pod_ingress_id);

CREATE TABLE IF NOT EXISTS pod_ingress_rule_backend (
    id                  SERIAL PRIMARY KEY,
    path                TEXT,
    port                INTEGER,
    pod_service_id      INTEGER DEFAULT NULL,
    pod_ingress_rule_id INTEGER DEFAULT NULL,
    pod_ingress_id      INTEGER DEFAULT NULL,
    sub_domain          VARCHAR(64) DEFAULT '',
    domain              VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE pod_ingress_rule_backend;

CREATE TABLE IF NOT EXISTS pod_service (
    id                  SERIAL PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    label               TEXT,
    annotation          TEXT,
    alias               VARCHAR(64) DEFAULT '',
    type                INTEGER DEFAULT NULL,
    selector            TEXT,
    external_ip         TEXT,
    service_cluster_ip  VARCHAR(64) DEFAULT '',
    metadata            TEXT,
    metadata_hash       VARCHAR(64) DEFAULT '',
    spec                TEXT,
    spec_hash           VARCHAR(64) DEFAULT '',
    pod_ingress_id      INTEGER DEFAULT NULL,
    pod_namespace_id    INTEGER DEFAULT NULL,
    pod_cluster_id      INTEGER DEFAULT NULL,
    epc_id              INTEGER DEFAULT NULL,
    az                  VARCHAR(64) DEFAULT '',
    region              VARCHAR(64) DEFAULT '',
    sub_domain          VARCHAR(64) DEFAULT '',
    domain              VARCHAR(64) DEFAULT '',
    uid                 VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at          TIMESTAMP DEFAULT NULL
);
TRUNCATE TABLE pod_service;
CREATE INDEX pod_service_pod_ingress_id_index ON pod_service (pod_ingress_id);
CREATE INDEX pod_service_pod_namespace_id_index ON pod_service (pod_namespace_id);
CREATE INDEX pod_service_pod_cluster_id_index ON pod_service (pod_cluster_id);
CREATE INDEX pod_service_domain_index ON pod_service (domain);

COMMENT ON COLUMN pod_service.label IS 'separated by ,';
COMMENT ON COLUMN pod_service.annotation IS 'separated by ,';
COMMENT ON COLUMN pod_service.type IS '1: ClusterIP 2: NodePort 3: LoadBalancer';
COMMENT ON COLUMN pod_service.selector IS 'separated by ,';
COMMENT ON COLUMN pod_service.external_ip IS 'separated by ,';
COMMENT ON COLUMN pod_service.metadata IS 'yaml format';
COMMENT ON COLUMN pod_service.spec IS 'yaml format';

CREATE TABLE IF NOT EXISTS pod_service_port (
    id                  SERIAL PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    protocol            VARCHAR(64) DEFAULT '',
    port                INTEGER,
    target_port         INTEGER,
    node_port           INTEGER,
    pod_service_id      INTEGER DEFAULT NULL,
    sub_domain          VARCHAR(64) DEFAULT '',
    domain              VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64),
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE pod_service_port;
CREATE INDEX pod_service_port_pod_service_id_index ON pod_service_port (pod_service_id);

CREATE TABLE IF NOT EXISTS pod_group (
    id                  SERIAL PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    alias               VARCHAR(64) DEFAULT '',
    type                INTEGER DEFAULT NULL,
    pod_num             INTEGER DEFAULT 1,
    label               TEXT,
    network_mode        INTEGER DEFAULT 1,
    metadata            TEXT,
    metadata_hash       VARCHAR(64) DEFAULT '',
    spec                TEXT,
    spec_hash           VARCHAR(64) DEFAULT '',
    pod_namespace_id    INTEGER DEFAULT NULL,
    pod_cluster_id      INTEGER DEFAULT NULL,
    az                  VARCHAR(64) DEFAULT '',
    region              VARCHAR(64) DEFAULT '',
    sub_domain          VARCHAR(64) DEFAULT '',
    domain              VARCHAR(64) DEFAULT '',
    uid                 VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at          TIMESTAMP DEFAULT NULL
);
TRUNCATE TABLE pod_group;
CREATE INDEX pod_group_pod_namespace_id_index ON pod_group (pod_namespace_id);
CREATE INDEX pod_group_pod_cluster_id_index ON pod_group (pod_cluster_id);
COMMENT ON COLUMN pod_group.type IS '1: Deployment 2: StatefulSet 3: ReplicationController';
COMMENT ON COLUMN pod_group.label IS 'separated by ,';
COMMENT ON COLUMN pod_group.metadata IS 'yaml format';
COMMENT ON COLUMN pod_group.spec IS 'yaml format';

CREATE TABLE IF NOT EXISTS pod_group_port (
    id                  SERIAL PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    protocol            VARCHAR(64) DEFAULT '',
    port                INTEGER,
    pod_group_id        INTEGER DEFAULT NULL,
    pod_service_id      INTEGER DEFAULT NULL,
    sub_domain          VARCHAR(64) DEFAULT '',
    domain              VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE pod_group_port;

CREATE TABLE IF NOT EXISTS pod_rs (
    id                  SERIAL PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    alias               VARCHAR(64) DEFAULT '',
    label               TEXT,
    pod_num             INTEGER DEFAULT 1,
    pod_group_id        INTEGER DEFAULT NULL,
    pod_namespace_id    INTEGER DEFAULT NULL,
    pod_cluster_id      INTEGER DEFAULT NULL,
    az                  VARCHAR(64) DEFAULT '',
    region              VARCHAR(64) DEFAULT '',
    sub_domain          VARCHAR(64) DEFAULT '',
    domain              VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at          TIMESTAMP DEFAULT NULL
);
TRUNCATE TABLE pod_rs;
CREATE INDEX pod_rs_pod_group_id_index ON pod_rs (pod_group_id);
CREATE INDEX pod_rs_pod_namespace_id_index ON pod_rs (pod_namespace_id);
COMMENT ON COLUMN pod_rs.label IS 'separated by ,';

CREATE TABLE IF NOT EXISTS pod (
    id                  SERIAL PRIMARY KEY,
    name                VARCHAR(256) DEFAULT '',
    alias               VARCHAR(64) DEFAULT '',
    label               TEXT,
    annotation          TEXT,
    env                 TEXT,
    container_ids       TEXT,
    state               INTEGER NOT NULL,
    pod_rs_id           INTEGER DEFAULT NULL,
    pod_group_id        INTEGER DEFAULT NULL,
    pod_service_id      INTEGER DEFAULT 0,
    pod_namespace_id    INTEGER DEFAULT NULL,
    pod_node_id         INTEGER DEFAULT NULL,
    pod_cluster_id      INTEGER DEFAULT NULL,
    epc_id              INTEGER DEFAULT NULL,
    az                  VARCHAR(64) DEFAULT '',
    region              VARCHAR(64) DEFAULT '',
    sub_domain          VARCHAR(64) DEFAULT '',
    domain              VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at          TIMESTAMP DEFAULT NULL
);
TRUNCATE TABLE pod;
CREATE INDEX pod_state_index ON pod (state);
CREATE INDEX pod_pod_rs_id_index ON pod (pod_rs_id);
CREATE INDEX pod_pod_group_id_index ON pod (pod_group_id);
CREATE INDEX pod_pod_namespace_id_index ON pod (pod_namespace_id);
CREATE INDEX pod_pod_node_id_index ON pod (pod_node_id);
CREATE INDEX pod_pod_cluster_id_index ON pod (pod_cluster_id);
CREATE INDEX pod_epc_id_index ON pod (epc_id);
CREATE INDEX pod_az_index ON pod (az);
CREATE INDEX pod_region_index ON pod (region);
CREATE INDEX pod_domain_index ON pod (domain);
COMMENT ON COLUMN pod.label IS 'separated by ,';
COMMENT ON COLUMN pod.annotation IS 'separated by ,';
COMMENT ON COLUMN pod.env IS 'separated by ,';
COMMENT ON COLUMN pod.container_ids IS 'separated by ,';
COMMENT ON COLUMN pod.state IS '0.Exception 1.Running';

CREATE TABLE IF NOT EXISTS config_map (
    id                  SERIAL PRIMARY KEY,
    name                VARCHAR(256) NOT NULL,
    data                TEXT,
    data_hash           VARCHAR(64) DEFAULT '',
    pod_namespace_id    INTEGER NOT NULL,
    pod_cluster_id      INTEGER NOT NULL,
    epc_id              INTEGER NOT NULL,
    az                  VARCHAR(64) DEFAULT '',
    region              VARCHAR(64) DEFAULT '',
    sub_domain          VARCHAR(64) DEFAULT '',
    domain              CHAR(64) NOT NULL,
    lcuuid              CHAR(64) NOT NULL,
    synced_at           TIMESTAMP DEFAULT NULL,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE config_map;
CREATE INDEX config_map_data_hash_index ON config_map (data_hash);
CREATE INDEX config_map_domain_index ON config_map (domain);
COMMENT ON COLUMN config_map.data IS 'yaml format';

CREATE TABLE IF NOT EXISTS pod_group_config_map_connection (
    id                  SERIAL PRIMARY KEY,
    pod_group_id        INTEGER NOT NULL,
    config_map_id       INTEGER NOT NULL,
    sub_domain          VARCHAR(64) DEFAULT '',
    domain              CHAR(64) NOT NULL,
    lcuuid              CHAR(64) NOT NULL,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE pod_group_config_map_connection;
CREATE INDEX pod_group_config_map_connection_pod_group_id_index ON pod_group_config_map_connection (pod_group_id);
CREATE INDEX pod_group_config_map_connection_config_map_id_index ON pod_group_config_map_connection (config_map_id);

-- Processes
CREATE TABLE IF NOT EXISTS process (
    id                  SERIAL PRIMARY KEY,
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
    start_time          TIMESTAMP NOT NULL DEFAULT NOW(),
    os_app_tags         TEXT,
    netns_id            BIGINT DEFAULT 0 CHECK (netns_id >= 0 AND netns_id <= 4294967295),
    sub_domain          VARCHAR(64) DEFAULT '',
    domain              VARCHAR(64) DEFAULT '',
    lcuuid              VARCHAR(64) DEFAULT '',
    container_id        VARCHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMP NOT NULL DEFAULT NOW(),
    deleted_at          TIMESTAMP DEFAULT NULL
);
TRUNCATE TABLE process;
COMMENT ON COLUMN process.os_app_tags IS 'separated by ,';
CREATE INDEX process_gid_update_index ON process (domain, sub_domain, gid, updated_at);
CREATE INDEX process_deleted_at_index ON process (deleted_at);

-- Custom Service
CREATE TABLE IF NOT EXISTS custom_service (
    id                  SERIAL PRIMARY KEY,
    name                VARCHAR(128) NOT NULL,
    type                INTEGER DEFAULT 0,
    resource            TEXT,
    epc_id              INTEGER DEFAULT 0,
    domain_id           INTEGER DEFAULT 0,
    domain              CHAR(64) DEFAULT '',
    team_id             INTEGER DEFAULT 1,
    lcuuid              CHAR(64) DEFAULT '',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE custom_service;
CREATE UNIQUE INDEX IF NOT EXISTS custom_service_name_idx ON custom_service(name);
COMMENT ON COLUMN custom_service.type IS '0: unknown 1: IP 2: PORT';
COMMENT ON COLUMN custom_service.domain IS 'reserved for backend';
COMMENT ON COLUMN custom_service.resource IS 'separated by ,';

-- Others
CREATE TABLE IF NOT EXISTS tap_type (
    id                  SERIAL PRIMARY KEY,
    name                VARCHAR(64) NOT NULL,
    type                INTEGER NOT NULL DEFAULT 1,
    region              VARCHAR(64),
    value               INTEGER NOT NULL,
    vlan                INTEGER,
    src_ip              VARCHAR(64),
    interface_index     BIGINT CHECK (interface_index > 0 AND interface_index <= 4294967295),
    interface_name      VARCHAR(64),
    sampling_rate       BIGINT CHECK (sampling_rate > 0 AND sampling_rate <= 4294967295),
    description         VARCHAR(256),
    lcuuid              VARCHAR(64)
);
TRUNCATE TABLE tap_type;
COMMENT ON COLUMN tap_type.type IS '1:packet, 2:sFlow, 3:NetFlow V5 4:NetStream v5';
COMMENT ON COLUMN tap_type.interface_index IS '1 ~ 2^32-1';
COMMENT ON COLUMN tap_type.sampling_rate IS '1 ~ 2^32-1';

CREATE TABLE IF NOT EXISTS third_party_device (
    id                  SERIAL PRIMARY KEY,
    epc_id              INTEGER DEFAULT 0,
    vm_id               INTEGER,
    curr_time           TIMESTAMP NOT NULL DEFAULT NOW(),
    sys_uptime          VARCHAR(32),
    type                INTEGER,
    state               INTEGER,
    errno               INTEGER DEFAULT 0,
    name                VARCHAR(256),
    label               VARCHAR(64),
    poolid              INTEGER DEFAULT 0,
    community           VARCHAR(256),
    mgmt_ip             VARCHAR(64),
    data_ip             VARCHAR(64),
    ctrl_ip             VARCHAR(64),
    ctrl_mac            VARCHAR(32),
    data1_mac           VARCHAR(32),
    data2_mac           VARCHAR(32),
    data3_mac           VARCHAR(32),
    launch_server       VARCHAR(64),
    user_name           VARCHAR(64),
    user_passwd         VARCHAR(64),
    vnc_port            INTEGER DEFAULT 0,
    brand               VARCHAR(64),
    sys_os              VARCHAR(64),
    mem_size            INTEGER,
    mem_used            INTEGER,
    mem_usage           VARCHAR(32),
    mem_data            VARCHAR(256),
    cpu_type            VARCHAR(128),
    cpu_num             INTEGER,
    cpu_data            VARCHAR(256),
    disk_size           INTEGER,
    dsk_num             INTEGER,
    disk_info           VARCHAR(1024),
    nic_num             INTEGER,
    nic_data            VARCHAR(256),
    rack_name           VARCHAR(256),
    userid              INTEGER,
    domain              VARCHAR(64),
    region              VARCHAR(64),
    lcuuid              VARCHAR(64),
    order_id            INTEGER,
    product_specification_lcuuid VARCHAR(64),
    role                INTEGER DEFAULT 1,
    create_time         TIMESTAMP,
    gateway             VARCHAR(64) DEFAULT '',
    raid_support        VARCHAR(64) DEFAULT ''
);
TRUNCATE TABLE third_party_device;
COMMENT ON COLUMN third_party_device.type IS '1.VM 2.Gateway 3.Compute 4.Network 5.Storage 6.Security';
COMMENT ON COLUMN third_party_device.state IS '0.Temp 1.run 2.stop 3.added to vdc 4.no add to vdc 5.to start 6.to stop';
COMMENT ON COLUMN third_party_device.errno IS '1.Operate, 2.Install, 3.Uninstall, 4.Status';
COMMENT ON COLUMN third_party_device.mem_size IS 'Unit: MB';
COMMENT ON COLUMN third_party_device.mem_used IS 'Unit: MB';
COMMENT ON COLUMN third_party_device.disk_size IS 'Unit: GB';
COMMENT ON COLUMN third_party_device.role IS '1. General Purpose, 2. Load Balancer, 3. Database, 4. Web Server, 5. APP Server, 6. Firewall, 7. Gateway, 8. VPN, 9. Storage, 10. WAF 13.DEEPFLOW_TOOL';
COMMENT ON COLUMN third_party_device.gateway IS 'gateway of the default route';
COMMENT ON COLUMN third_party_device.raid_support IS 'must be a subset of RAID 0, 1, 5, 6, 10, 50, 60';

-- Genesis
CREATE TABLE IF NOT EXISTS genesis_vpc (
    lcuuid          VARCHAR(64),
    node_ip         VARCHAR(48),
    vtap_id         INTEGER,
    name            VARCHAR(256),
    PRIMARY KEY (lcuuid, vtap_id, node_ip)
);
TRUNCATE TABLE genesis_vpc;

CREATE TABLE IF NOT EXISTS genesis_network (
    name            VARCHAR(256),
    lcuuid          VARCHAR(64),
    segmentation_id INTEGER,
    net_type        INTEGER,
    external        SMALLINT,
    vpc_lcuuid      VARCHAR(64),
    vtap_id         INTEGER,
    node_ip         VARCHAR(48),
    PRIMARY KEY (lcuuid, vtap_id, node_ip)
);
TRUNCATE TABLE genesis_network;

CREATE TABLE IF NOT EXISTS genesis_port (
    lcuuid          VARCHAR(64),
    type            INTEGER,
    device_type     INTEGER,
    mac             VARCHAR(32),
    device_lcuuid   VARCHAR(64),
    network_lcuuid  VARCHAR(64),
    vpc_lcuuid      VARCHAR(64),
    vtap_id         INTEGER,
    node_ip         VARCHAR(48),
    PRIMARY KEY (lcuuid, vtap_id, node_ip)
);
TRUNCATE TABLE genesis_port;

CREATE TABLE IF NOT EXISTS genesis_vinterface (
    netns_id              BIGINT DEFAULT 0 CHECK (netns_id >= 0 AND netns_id <= 4294967295),
    lcuuid                VARCHAR(64),
    name                  VARCHAR(64),
    mac                   VARCHAR(32),
    ips                   TEXT,
    tap_name              VARCHAR(64),
    tap_mac               VARCHAR(32),
    device_lcuuid         VARCHAR(64),
    device_name           VARCHAR(512),
    device_type           VARCHAR(64),
    if_type               VARCHAR(64) DEFAULT '',
    host_ip               VARCHAR(48),
    node_ip               VARCHAR(48),
    last_seen             TIMESTAMP,
    vtap_id               INTEGER,
    kubernetes_cluster_id VARCHAR(64),
    team_id               INTEGER DEFAULT 1,
    PRIMARY KEY (lcuuid, vtap_id, node_ip)
);
TRUNCATE TABLE genesis_vinterface;
CREATE INDEX vinterface_node_ip_index ON genesis_vinterface (node_ip);

CREATE TABLE IF NOT EXISTS genesis_ip (
    lcuuid              VARCHAR(64),
    ip                  VARCHAR(64),
    vinterface_lcuuid   VARCHAR(64),
    node_ip             VARCHAR(48),
    last_seen           TIMESTAMP,
    vtap_id             INTEGER,
    masklen             INTEGER DEFAULT 0,
    PRIMARY KEY (lcuuid, vtap_id, node_ip)
);
TRUNCATE TABLE genesis_ip;

CREATE TABLE IF NOT EXISTS genesis_vip (
    lcuuid      VARCHAR(64),
    ip          VARCHAR(64),
    vtap_id     INTEGER,
    node_ip     VARCHAR(48),
    PRIMARY KEY (lcuuid, vtap_id, node_ip)
);
TRUNCATE TABLE genesis_vip;

CREATE TABLE IF NOT EXISTS genesis_host (
    lcuuid      VARCHAR(64),
    hostname    VARCHAR(256),
    ip          VARCHAR(64),
    vtap_id     INTEGER,
    node_ip     VARCHAR(48),
    PRIMARY KEY (lcuuid, vtap_id, node_ip)
);
TRUNCATE TABLE genesis_host;

CREATE TABLE IF NOT EXISTS genesis_vm (
    lcuuid          VARCHAR(64),
    name            VARCHAR(256),
    label           VARCHAR(64),
    vpc_lcuuid      VARCHAR(64),
    launch_server   VARCHAR(64),
    node_ip         VARCHAR(48),
    state           INTEGER,
    vtap_id         INTEGER,
    created_at      TIMESTAMP,
    PRIMARY KEY (lcuuid, vtap_id, node_ip)
);
TRUNCATE TABLE genesis_vm;

CREATE TABLE IF NOT EXISTS genesis_lldp (
    lcuuid                  VARCHAR(64),
    host_ip                 VARCHAR(48),
    host_interface          VARCHAR(64),
    node_ip                 VARCHAR(48),
    system_name             VARCHAR(512),
    management_address      VARCHAR(512),
    vinterface_lcuuid       VARCHAR(512),
    vinterface_description  VARCHAR(512),
    vtap_id                 INTEGER,
    last_seen               TIMESTAMP,
    PRIMARY KEY (lcuuid, vtap_id, node_ip)
);
TRUNCATE TABLE genesis_lldp;

CREATE TABLE IF NOT EXISTS genesis_process (
    netns_id            BIGINT DEFAULT 0 CHECK (netns_id >= 0 AND netns_id <= 4294967295),
    vtap_id             INTEGER NOT NULL DEFAULT 0,
    pid                 INTEGER NOT NULL,
    lcuuid              VARCHAR(64) DEFAULT '',
    name                TEXT,
    process_name        TEXT,
    cmd_line            TEXT,
    user_name           VARCHAR(256) DEFAULT '',
    container_id        VARCHAR(64) DEFAULT '',
    os_app_tags         TEXT,
    node_ip             VARCHAR(48) DEFAULT '',
    start_time          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (lcuuid, vtap_id, node_ip)
);
COMMENT ON COLUMN genesis_process.os_app_tags IS 'separated by ,';
TRUNCATE TABLE genesis_process;
CREATE INDEX process_node_ip_index ON genesis_process (node_ip);

CREATE TABLE IF NOT EXISTS genesis_storage (
    vtap_id     INTEGER NOT NULL PRIMARY KEY,
    node_ip     VARCHAR(48)
);
TRUNCATE TABLE genesis_storage;

CREATE TABLE IF NOT EXISTS genesis_cluster (
    id          VARCHAR(64) NOT NULL PRIMARY KEY,
    node_ip     VARCHAR(48)
);
TRUNCATE TABLE genesis_cluster;

-- ClickHouse dictionary

CREATE TABLE IF NOT EXISTS ch_region (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    icon_id                 INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_region;
CREATE INDEX ch_region_updated_at_index ON ch_region(updated_at);

CREATE TABLE IF NOT EXISTS ch_az (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    icon_id                 INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_az;
CREATE INDEX ch_az_updated_at_index ON ch_az(updated_at);

CREATE TABLE IF NOT EXISTS ch_l3_epc (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    uid                     VARCHAR(64),
    icon_id                 INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_l3_epc;
CREATE INDEX ch_l3_epc_updated_at_index ON ch_l3_epc(updated_at);

CREATE TABLE IF NOT EXISTS ch_subnet (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    icon_id                 INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    sub_domain_id           INTEGER,
    l3_epc_id               INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_subnet;
CREATE INDEX ch_subnet_updated_at_index ON ch_subnet(updated_at);

CREATE TABLE IF NOT EXISTS ch_ip_relation (
    l3_epc_id           INTEGER NOT NULL,
    ip                  VARCHAR(64) NOT NULL,
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
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (l3_epc_id, ip)
);
TRUNCATE TABLE ch_ip_relation;
CREATE INDEX ch_ip_relation_updated_at_index ON ch_ip_relation(updated_at);

CREATE TABLE IF NOT EXISTS ch_pod_cluster (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    icon_id                 INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    sub_domain_id           INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_pod_cluster;
CREATE INDEX ch_pod_cluster_updated_at_index ON ch_pod_cluster(updated_at);

CREATE TABLE IF NOT EXISTS ch_pod_node (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    pod_cluster_id          INTEGER,
    icon_id                 INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    sub_domain_id           INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_pod_node;
CREATE INDEX ch_pod_node_updated_at_index ON ch_pod_node(updated_at);

CREATE TABLE IF NOT EXISTS ch_pod_ns (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    icon_id                 INTEGER,
    pod_cluster_id          INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    sub_domain_id           INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_pod_ns;
CREATE INDEX ch_pod_ns_updated_at_index ON ch_pod_ns(updated_at);

CREATE TABLE IF NOT EXISTS ch_pod_group (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    pod_group_type          INTEGER,
    icon_id                 INTEGER,
    pod_cluster_id          INTEGER,
    pod_ns_id               INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    sub_domain_id           INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_pod_group;
CREATE INDEX ch_pod_group_updated_at_index ON ch_pod_group(updated_at);

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
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_pod;
CREATE INDEX ch_pod_updated_at_index ON ch_pod(updated_at);

CREATE TABLE IF NOT EXISTS ch_device (
    devicetype              INTEGER NOT NULL,
    deviceid                INTEGER NOT NULL,
    name                    TEXT,
    uid                     VARCHAR(64),
    icon_id                 INTEGER,
    ip                      VARCHAR(64),
    hostname                VARCHAR(256),
    team_id                 INTEGER,
    domain_id               INTEGER,
    sub_domain_id           INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (devicetype, deviceid)
);
TRUNCATE TABLE ch_device;
CREATE INDEX ch_device_updated_at_index ON ch_device(updated_at);

CREATE TABLE IF NOT EXISTS ch_lb_listener (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    team_id                 INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_lb_listener;
CREATE INDEX ch_lb_listener_updated_at_index ON ch_lb_listener(updated_at);

CREATE TABLE IF NOT EXISTS ch_pod_ingress (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    pod_cluster_id          INTEGER,
    pod_ns_id               INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    sub_domain_id           INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_pod_ingress;
CREATE INDEX ch_pod_ingress_updated_at_index ON ch_pod_ingress(updated_at);

CREATE TABLE IF NOT EXISTS ch_pod_k8s_label (
    id                      INTEGER NOT NULL,
    key                     VARCHAR(256) NOT NULL,
    value                   VARCHAR(256),
    l3_epc_id               INTEGER,
    pod_ns_id               INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    sub_domain_id           INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, key)
);
TRUNCATE TABLE ch_pod_k8s_label;
CREATE INDEX ch_pod_k8s_label_id_updated_at_index ON ch_pod_k8s_label(domain_id, sub_domain_id, id, updated_at);
CREATE INDEX ch_pod_k8s_label_updated_at_index ON ch_pod_k8s_label(updated_at);

CREATE TABLE IF NOT EXISTS ch_pod_k8s_labels (
    id                  INTEGER NOT NULL PRIMARY KEY,
    labels              TEXT,
    l3_epc_id           INTEGER,
    pod_ns_id           INTEGER,
    team_id             INTEGER,
    domain_id           INTEGER,
    sub_domain_id       INTEGER,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_pod_k8s_labels;
CREATE INDEX ch_pod_k8s_labels_updated_at_index ON ch_pod_k8s_labels(updated_at);

CREATE TABLE IF NOT EXISTS ch_chost_cloud_tag (
    id                      INTEGER NOT NULL,
    key                     VARCHAR(256) NOT NULL,
    value                   VARCHAR(256),
    team_id                 INTEGER,
    domain_id               INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, key)
);
TRUNCATE TABLE ch_chost_cloud_tag;
CREATE INDEX ch_chost_cloud_tag_id_updated_at_index ON ch_chost_cloud_tag(domain_id, id, updated_at);
CREATE INDEX ch_chost_cloud_tag_updated_at_index ON ch_chost_cloud_tag(updated_at);

CREATE TABLE IF NOT EXISTS ch_pod_ns_cloud_tag (
    id                      INTEGER NOT NULL,
    key                     VARCHAR(256) NOT NULL,
    value                   VARCHAR(256),
    team_id                 INTEGER,
    domain_id               INTEGER,
    sub_domain_id           INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, key)
);
TRUNCATE TABLE ch_pod_ns_cloud_tag;
CREATE INDEX ch_pod_ns_cloud_tag_id_updated_at_index ON ch_pod_ns_cloud_tag(domain_id, sub_domain_id, id, updated_at);
CREATE INDEX ch_pod_ns_cloud_tag_updated_at_index ON ch_pod_ns_cloud_tag(updated_at);

CREATE TABLE IF NOT EXISTS ch_chost_cloud_tags (
    id                      INTEGER NOT NULL PRIMARY KEY,
    cloud_tags              TEXT,
    team_id                 INTEGER,
    domain_id               INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_chost_cloud_tags;
CREATE INDEX ch_chost_cloud_tags_updated_at_index ON ch_chost_cloud_tags(updated_at);

CREATE TABLE IF NOT EXISTS ch_pod_ns_cloud_tags (
    id                      INTEGER NOT NULL PRIMARY KEY,
    cloud_tags              TEXT,
    team_id                 INTEGER,
    domain_id               INTEGER,
    sub_domain_id           INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_pod_ns_cloud_tags;
CREATE INDEX ch_pod_ns_cloud_tags_updated_at_index ON ch_pod_ns_cloud_tags(updated_at);

CREATE TABLE IF NOT EXISTS ch_os_app_tag (
    id                      INTEGER NOT NULL,
    key                     VARCHAR(256) NOT NULL,
    value                   VARCHAR(256),
    team_id                 INTEGER,
    domain_id               INTEGER,
    sub_domain_id           INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, key)
);
TRUNCATE TABLE ch_os_app_tag;
CREATE INDEX ch_os_app_tag_updated_at_index ON ch_os_app_tag(updated_at);

CREATE TABLE IF NOT EXISTS ch_os_app_tags (
    id                      INTEGER NOT NULL PRIMARY KEY,
    os_app_tags             TEXT,
    team_id                 INTEGER,
    domain_id               INTEGER,
    sub_domain_id           INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_os_app_tags;
CREATE INDEX ch_os_app_tags_updated_at_index ON ch_os_app_tags(updated_at);

CREATE TABLE IF NOT EXISTS ch_gprocess (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    TEXT,
    icon_id                 INTEGER,
    chost_id                INTEGER,
    l3_epc_id               INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    sub_domain_id           INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_gprocess;
CREATE INDEX ch_gprocess_updated_at_index ON ch_gprocess(updated_at);

CREATE TABLE IF NOT EXISTS ch_pod_service_k8s_label (
    id                      INTEGER NOT NULL,
    key                     VARCHAR(256) NOT NULL,
    value                   VARCHAR(256),
    l3_epc_id               INTEGER,
    pod_ns_id               INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    sub_domain_id           INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, key)
);
TRUNCATE TABLE ch_pod_service_k8s_label;
CREATE INDEX ch_pod_service_k8s_label_id_updated_at_index ON ch_pod_service_k8s_label(domain_id, sub_domain_id, id, updated_at);
CREATE INDEX ch_pod_service_k8s_label_updated_at_index ON ch_pod_service_k8s_label(updated_at);

CREATE TABLE IF NOT EXISTS ch_pod_service_k8s_labels (
    id                      INTEGER NOT NULL PRIMARY KEY,
    labels                  TEXT,
    l3_epc_id               INTEGER,
    pod_ns_id               INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    sub_domain_id           INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_pod_service_k8s_labels;
CREATE INDEX ch_pod_service_k8s_labels_updated_at_index ON ch_pod_service_k8s_labels(updated_at);

CREATE TABLE IF NOT EXISTS ch_pod_k8s_annotation (
    id                      INTEGER NOT NULL,
    key                     VARCHAR(256) NOT NULL,
    value                   VARCHAR(256),
    l3_epc_id               INTEGER,
    pod_ns_id               INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    sub_domain_id           INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, key)
);
TRUNCATE TABLE ch_pod_k8s_annotation;
CREATE INDEX ch_pod_k8s_annotation_id_updated_at_index ON ch_pod_k8s_annotation(domain_id, sub_domain_id, id, updated_at);
CREATE INDEX ch_pod_k8s_annotation_updated_at_index ON ch_pod_k8s_annotation(updated_at);

CREATE TABLE IF NOT EXISTS ch_pod_k8s_annotations (
    id                      INTEGER NOT NULL PRIMARY KEY,
    annotations             TEXT,
    l3_epc_id               INTEGER,
    pod_ns_id               INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    sub_domain_id           INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_pod_k8s_annotations;
CREATE INDEX ch_pod_k8s_annotations_updated_at_index ON ch_pod_k8s_annotations(updated_at);

CREATE TABLE IF NOT EXISTS ch_pod_service_k8s_annotation (
    id                      INTEGER NOT NULL,
    key                     VARCHAR(256) NOT NULL,
    value                   VARCHAR(256),
    l3_epc_id               INTEGER,
    pod_ns_id               INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    sub_domain_id           INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, key)
);
TRUNCATE TABLE ch_pod_service_k8s_annotation;
CREATE INDEX ch_pod_service_k8s_annotation_id_updated_at_index ON ch_pod_service_k8s_annotation(domain_id, sub_domain_id, id, updated_at);
CREATE INDEX ch_pod_service_k8s_annotation_updated_at_index ON ch_pod_service_k8s_annotation(updated_at);

CREATE TABLE IF NOT EXISTS ch_pod_service_k8s_annotations (
    id                      INTEGER NOT NULL PRIMARY KEY,
    annotations             TEXT,
    l3_epc_id               INTEGER,
    pod_ns_id               INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    sub_domain_id           INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_pod_service_k8s_annotations;
CREATE INDEX ch_pod_service_k8s_annotations_updated_at_index ON ch_pod_service_k8s_annotations(updated_at);

CREATE TABLE IF NOT EXISTS ch_pod_k8s_env (
    id                      INTEGER NOT NULL,
    key                     VARCHAR(256) NOT NULL,
    value                   VARCHAR(256),
    l3_epc_id               INTEGER,
    pod_ns_id               INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    sub_domain_id           INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, key)
);
TRUNCATE TABLE ch_pod_k8s_env;
CREATE INDEX ch_pod_k8s_env_id_updated_at_index ON ch_pod_k8s_env(domain_id, sub_domain_id, id, updated_at);
CREATE INDEX ch_pod_k8s_env_updated_at_index ON ch_pod_k8s_env(updated_at);

CREATE TABLE IF NOT EXISTS ch_pod_k8s_envs (
    id                      INTEGER NOT NULL PRIMARY KEY,
    envs                    TEXT,
    l3_epc_id               INTEGER,
    pod_ns_id               INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    sub_domain_id           INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_pod_k8s_envs;
CREATE INDEX ch_pod_k8s_envs_updated_at_index ON ch_pod_k8s_envs(updated_at);


CREATE TABLE IF NOT EXISTS ch_pod_service (
    id                          INTEGER NOT NULL PRIMARY KEY,
    name                        VARCHAR(256),
    pod_cluster_id              INTEGER,
    pod_ns_id                   INTEGER,
    team_id                     INTEGER,
    domain_id                   INTEGER,
    sub_domain_id               INTEGER,
    updated_at                  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_pod_service;
CREATE INDEX ch_pod_service_updated_at_index ON ch_pod_service(updated_at);

CREATE TABLE IF NOT EXISTS ch_chost (
    id                          INTEGER NOT NULL PRIMARY KEY,
    name                        VARCHAR(256),
    host_id                     INTEGER,
    l3_epc_id                   INTEGER,
    ip                          VARCHAR(64),
    subnet_id                   INTEGER,
    hostname                    VARCHAR(256),
    team_id                     INTEGER,
    domain_id                   INTEGER,
    updated_at                  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_chost;
CREATE INDEX ch_chost_updated_at_index ON ch_chost(updated_at);

CREATE TABLE IF NOT EXISTS ch_biz_service (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256),
    service_group_name      VARCHAR(256),
    icon_id                 INTEGER,
    team_id                 INTEGER,
    domain_id               INTEGER,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_biz_service;
CREATE INDEX ch_biz_service_updated_at_index ON ch_biz_service(updated_at);

CREATE TABLE IF NOT EXISTS ch_vtap_port (
    vtap_id                 INTEGER NOT NULL,
    tap_port                BIGINT NOT NULL,
    name                    VARCHAR(256),
    mac_type                INTEGER DEFAULT 1,
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
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (vtap_id, tap_port)
);
TRUNCATE TABLE ch_vtap_port;
COMMENT ON COLUMN ch_vtap_port.mac_type IS '1:tap_mac,2:mac';
CREATE INDEX ch_vtap_port_updated_at_index ON ch_vtap_port(updated_at);

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
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_vtap;
CREATE INDEX ch_vtap_updated_at_index ON ch_vtap(updated_at);

CREATE TABLE IF NOT EXISTS ch_tap_type (
    value                   INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256) NOT NULL,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_tap_type;
CREATE INDEX ch_tap_type_updated_at_index ON ch_tap_type(updated_at);

CREATE TABLE IF NOT EXISTS ch_node_type (
    resource_type           INTEGER NOT NULL DEFAULT 0 PRIMARY KEY,
    node_type               VARCHAR(256),
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_node_type;
CREATE INDEX ch_node_type_updated_at_index ON ch_node_type(updated_at);


CREATE TABLE IF NOT EXISTS ch_string_enum (
    tag_name                VARCHAR(256) NOT NULL,
    value                   VARCHAR(256) NOT NULL,
    name_zh                 VARCHAR(256),
    name_en                 VARCHAR(256),
    description_zh          VARCHAR(256),
    description_en          VARCHAR(256),
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tag_name, value)
);
TRUNCATE TABLE ch_string_enum;
CREATE INDEX ch_string_enum_updated_at_index ON ch_string_enum(updated_at);

CREATE TABLE IF NOT EXISTS ch_int_enum (
    tag_name                VARCHAR(256) NOT NULL,
    value                   INTEGER DEFAULT 0,
    name_zh                 VARCHAR(256),
    name_en                 VARCHAR(256),
    description_zh          VARCHAR(256),
    description_en          VARCHAR(256),
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tag_name, value)
);
TRUNCATE TABLE ch_int_enum;
CREATE INDEX ch_int_enum_updated_at_index ON ch_int_enum(updated_at);

CREATE TABLE IF NOT EXISTS ch_app_label (
    label_name_id      INTEGER NOT NULL,
    label_value_id     INTEGER NOT NULL,
    label_value        TEXT,
    updated_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (label_name_id, label_value_id)
);
TRUNCATE TABLE ch_app_label;
CREATE INDEX ch_app_label_updated_at_index ON ch_app_label(updated_at);

CREATE TABLE IF NOT EXISTS ch_target_label (
    metric_id          INTEGER NOT NULL,
    label_name_id      INTEGER NOT NULL,
    target_id          INTEGER NOT NULL,
    label_value        VARCHAR(256) NOT NULL,
    updated_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (metric_id, label_name_id, target_id)
);
TRUNCATE TABLE ch_target_label;
CREATE INDEX ch_target_label_updated_at_index ON ch_target_label(updated_at);

CREATE TABLE IF NOT EXISTS ch_prometheus_label_name (
    id                  INTEGER NOT NULL PRIMARY KEY,
    name                VARCHAR(256) NOT NULL,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_prometheus_label_name;
CREATE INDEX ch_prometheus_label_name_updated_at_index ON ch_prometheus_label_name(updated_at);

CREATE TABLE IF NOT EXISTS ch_prometheus_metric_name (
    id                  INTEGER NOT NULL PRIMARY KEY,
    name                VARCHAR(256) NOT NULL,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_prometheus_metric_name;
CREATE INDEX ch_prometheus_metric_name_updated_at_index ON ch_prometheus_metric_name(updated_at);

CREATE TABLE IF NOT EXISTS ch_prometheus_metric_app_label_layout (
    id                          INTEGER NOT NULL PRIMARY KEY,
    metric_name                 VARCHAR(256) NOT NULL,
    app_label_name              VARCHAR(256) NOT NULL,
    app_label_column_index      SMALLINT NOT NULL,
    updated_at                  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_prometheus_metric_app_label_layout;
CREATE INDEX ch_prometheus_metric_app_label_layout_updated_at_index ON ch_prometheus_metric_app_label_layout(updated_at);

CREATE TABLE IF NOT EXISTS ch_prometheus_target_label_layout (
    target_id                   INTEGER NOT NULL PRIMARY KEY,
    target_label_names          TEXT,
    target_label_values         TEXT,
    updated_at                  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_prometheus_target_label_layout;
CREATE INDEX ch_prometheus_target_label_layout_updated_at_index ON ch_prometheus_target_label_layout(updated_at);

CREATE TABLE IF NOT EXISTS ch_policy (
    tunnel_type     INTEGER NOT NULL,
    acl_gid         INTEGER NOT NULL,
    id              INTEGER,
    name            VARCHAR(256),
    team_id         INTEGER DEFAULT 1,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tunnel_type, acl_gid)
);
TRUNCATE TABLE ch_policy;
CREATE INDEX ch_policy_updated_at_index ON ch_policy(updated_at);

CREATE TABLE IF NOT EXISTS ch_npb_tunnel (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(256),
    team_id         INTEGER DEFAULT 1,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_npb_tunnel;
CREATE INDEX ch_npb_tunnel_updated_at_index ON ch_npb_tunnel(updated_at);

CREATE TABLE IF NOT EXISTS ch_alarm_policy (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(256),
    info            TEXT,
    user_id         INTEGER,
    team_id         INTEGER DEFAULT 1,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_alarm_policy;
CREATE INDEX ch_alarm_policy_updated_at_index ON ch_alarm_policy(updated_at);

CREATE TABLE IF NOT EXISTS ch_user (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(256),
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_user;
CREATE INDEX ch_user_updated_at_index ON ch_user(updated_at);

CREATE TABLE IF NOT EXISTS ch_custom_biz_service (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(256),
    uid             VARCHAR(64),
    icon_id         INTEGER,
    team_id         INTEGER DEFAULT 1,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_custom_biz_service;
CREATE INDEX ch_custom_biz_service_updated_at_index ON ch_custom_biz_service(updated_at);

CREATE TABLE IF NOT EXISTS ch_custom_biz_service_filter (
    id               SERIAL PRIMARY KEY,
    client_filter    TEXT,
    server_filter    TEXT,
    updated_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE ch_custom_biz_service_filter;
CREATE INDEX ch_custom_biz_service_filter_updated_at_index ON ch_custom_biz_service_filter(updated_at);

-- NPB/PCAP
CREATE TABLE IF NOT EXISTS acl (
    id                     SERIAL PRIMARY KEY,
    business_id            INTEGER NOT NULL,
    name                   VARCHAR(64),
    team_id                INTEGER DEFAULT 1,
    type                   INTEGER DEFAULT 2,
    tap_type               INTEGER DEFAULT 3,
    state                  INTEGER DEFAULT 1,
    valid                  INTEGER DEFAULT 1,
    invalid_description    TEXT,
    applications           VARCHAR(64) NOT NULL,
    epc_id                 INTEGER,
    src_group_ids          TEXT,
    dst_group_ids          TEXT,
    protocol               INTEGER,
    src_ports              TEXT,
    dst_ports              TEXT,
    vlan                   INTEGER,
    created_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lcuuid                 VARCHAR(64)
);
TRUNCATE TABLE acl;
COMMENT ON COLUMN acl.type IS '1-epc; 2-custom';
COMMENT ON COLUMN acl.tap_type IS '1-WAN; 3-LAN';
COMMENT ON COLUMN acl.state IS '0-disable; 1-enable';
COMMENT ON COLUMN acl.applications IS 'separated by , (1-performance analysis; 2-backpacking; 6-npb)';
COMMENT ON COLUMN acl.src_group_ids IS 'separated by ,';
COMMENT ON COLUMN acl.dst_group_ids IS 'separated by ,';
COMMENT ON COLUMN acl.src_ports IS 'separated by ,';
COMMENT ON COLUMN acl.dst_ports IS 'separated by ,';
COMMENT ON COLUMN acl.valid IS '0-invalid; 1-valid';

CREATE TABLE IF NOT EXISTS resource_group (
    id                      SERIAL PRIMARY KEY,
    team_id                 INTEGER DEFAULT 1,
    business_id             INTEGER NOT NULL,
    lcuuid                  VARCHAR(64) NOT NULL,
    name                    VARCHAR(200) NOT NULL DEFAULT '',
    type                    INTEGER NOT NULL,
    ip_type                 INTEGER,
    ips                     TEXT,
    vm_ids                  TEXT,
    vl2_ids                 TEXT,
    epc_id                  INTEGER,
    pod_cluster_id          INTEGER,
    extra_info_ids          TEXT,
    lb_id                   INTEGER,
    lb_listener_id          INTEGER,
    icon_id                 INTEGER DEFAULT -2,
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE resource_group;
COMMENT ON COLUMN resource_group.type IS '3: anonymous vm, 4: anonymous ip, 5: anonymous pod, 6: anonymous pod_group, 8: anonymous pod_service, 81: anonymous pod_service as pod_group, 14: anonymous vl2';
COMMENT ON COLUMN resource_group.ip_type IS '1: single ip, 2: ip range, 3: cidr, 4.mix [1, 2, 3]';
COMMENT ON COLUMN resource_group.ips IS 'ips separated by ,';
COMMENT ON COLUMN resource_group.vm_ids IS 'vm ids separated by ,';
COMMENT ON COLUMN resource_group.vl2_ids IS 'vl2 ids separated by ,';
COMMENT ON COLUMN resource_group.extra_info_ids IS 'resource group extra info ids separated by ,';

CREATE TABLE IF NOT EXISTS resource_group_extra_info (
    id                     SERIAL PRIMARY KEY,
    team_id                INTEGER DEFAULT 1,
    resource_type          INTEGER NOT NULL,
    resource_id            INTEGER NOT NULL,
    resource_sub_type      INTEGER,
    pod_namespace_id       INTEGER,
    resource_name          VARCHAR(256) NOT NULL
);
TRUNCATE TABLE resource_group_extra_info;
COMMENT ON COLUMN resource_group_extra_info.resource_type IS '1: epc, 2: vm, 3: pod_service, 4: pod_group, 5: vl2, 6: pod_cluster, 7: pod';

CREATE TABLE IF NOT EXISTS group_acl (
    id                     SERIAL PRIMARY KEY,
    team_id                INTEGER DEFAULT 1,
    group_id               INTEGER NOT NULL,
    acl_id                 INTEGER NOT NULL,
    lcuuid                 VARCHAR(64)
);
TRUNCATE TABLE group_acl;

CREATE TABLE IF NOT EXISTS policy_acl_group (
    id                      SERIAL PRIMARY KEY,
    team_id                 INTEGER DEFAULT 1,
    acl_ids                 TEXT NOT NULL,
    count                   INTEGER NOT NULL
);
TRUNCATE TABLE policy_acl_group;
COMMENT ON COLUMN policy_acl_group.acl_ids IS 'separated by ,';

CREATE TABLE IF NOT EXISTS npb_policy (
    id                     SERIAL PRIMARY KEY,
    user_id                INTEGER DEFAULT 1,
    team_id                INTEGER DEFAULT 1,
    name                   VARCHAR(64),
    state                  INTEGER DEFAULT 1,
    business_id            INTEGER NOT NULL,
    direction              SMALLINT DEFAULT 1,
    vni                    INTEGER,
    npb_tunnel_id          INTEGER,
    distribute             SMALLINT DEFAULT 1,
    payload_slice          INTEGER DEFAULT NULL,
    acl_id                 INTEGER,
    policy_acl_group_id    INTEGER,
    vtap_type              SMALLINT,
    vtap_ids               TEXT,
    vtap_group_ids         TEXT,
    created_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lcuuid                 VARCHAR(64)
);
TRUNCATE TABLE npb_policy;
COMMENT ON COLUMN npb_policy.state IS '0-disable; 1-enable';
COMMENT ON COLUMN npb_policy.direction IS '1-all; 2-forward; 3-backward;';
COMMENT ON COLUMN npb_policy.distribute IS '0-drop, 1-distribute';
COMMENT ON COLUMN npb_policy.vtap_type IS '1-vtap; 2-vtap_group';
COMMENT ON COLUMN npb_policy.vtap_ids IS 'separated by ,';
COMMENT ON COLUMN npb_policy.vtap_group_ids IS 'separated by ,';


CREATE TABLE IF NOT EXISTS npb_tunnel (
    id                  SERIAL PRIMARY KEY,
    user_id             INTEGER DEFAULT 1,
    team_id             INTEGER DEFAULT 1,
    name                VARCHAR(64) NOT NULL,
    ip                  VARCHAR(64),
    type                INTEGER,
    vni_input_type      SMALLINT DEFAULT 1,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lcuuid              VARCHAR(64)
);
TRUNCATE TABLE npb_tunnel;
COMMENT ON COLUMN npb_tunnel.type IS '(0-VXLAN；1-ERSPAN)';
COMMENT ON COLUMN npb_tunnel.vni_input_type IS '1. entire one 2. two parts';
COMMENT ON COLUMN npb_tunnel.created_at IS 'Timestamp when the record was created';
COMMENT ON COLUMN npb_tunnel.updated_at IS 'Timestamp when the record was last updated';

CREATE TABLE IF NOT EXISTS pcap_policy (
    id                     SERIAL PRIMARY KEY,
    name                   VARCHAR(64),
    state                  INTEGER DEFAULT 1,
    business_id            INTEGER NOT NULL,
    acl_id                 INTEGER,
    vtap_type              SMALLINT,
    vtap_ids               TEXT,
    vtap_group_ids         TEXT,
    payload_slice          INTEGER,
    policy_acl_group_id    INTEGER,
    user_id                INTEGER,
    created_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lcuuid                 VARCHAR(64),
    team_id                INTEGER DEFAULT 1
);
TRUNCATE TABLE pcap_policy;
COMMENT ON COLUMN pcap_policy.state IS '0-disable; 1-enable';
COMMENT ON COLUMN pcap_policy.vtap_type IS '1-vtap; 2-vtap_group';
COMMENT ON COLUMN pcap_policy.vtap_ids IS 'separated by ,';
COMMENT ON COLUMN pcap_policy.vtap_group_ids IS 'separated by ,';

-- Alerts/Reports
CREATE TABLE IF NOT EXISTS alarm_label (
    id                      SERIAL PRIMARY KEY,
    alarm_id                INTEGER NOT NULL,
    label_name              TEXT
);
TRUNCATE TABLE alarm_label;

CREATE TABLE IF NOT EXISTS alarm_policy (
    id                      SERIAL PRIMARY KEY,
    team_id                 INTEGER DEFAULT 1,
    sub_view_id             INTEGER,
    sub_view_type           SMALLINT DEFAULT 0,
    sub_view_name           TEXT,
    sub_view_url            TEXT,
    sub_view_params         TEXT,
    sub_view_metrics        TEXT,
    sub_view_extra          TEXT,
    user_id                 INTEGER,
    name                    VARCHAR(128) NOT NULL,
    level                   SMALLINT NOT NULL,
    state                   SMALLINT DEFAULT 1,
    app_type                SMALLINT NOT NULL,
    sub_type                SMALLINT DEFAULT 1,
    deleted                 SMALLINT DEFAULT 0,
    alert_time              BIGINT CHECK (alert_time > 0 AND alert_time <= 4294967295),
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at              TIMESTAMP DEFAULT NULL,
    contrast_type           SMALLINT NOT NULL DEFAULT 1,
    target_line_uid         TEXT,
    target_line_name        TEXT,
    target_field            TEXT,
    data_level              VARCHAR(64) NOT NULL DEFAULT '1m',
    upper_threshold         DOUBLE PRECISION,
    lower_threshold         DOUBLE PRECISION,
    agg                     SMALLINT DEFAULT 0,
    delay                   SMALLINT DEFAULT 1,
    threshold_critical      TEXT,
    threshold_error         TEXT,
    threshold_warning       TEXT,
    trigger_nodata_event    SMALLINT,
    query_url               TEXT,
    query_params            TEXT,
    query_conditions        TEXT,
    tag_conditions          TEXT,
    monitoring_frequency    VARCHAR(64) DEFAULT '1m',
    monitoring_interval     VARCHAR(64) DEFAULT '1m',
    trigger_info_event      INTEGER DEFAULT 0,
    trigger_recovery_event  INTEGER DEFAULT 1,
    recovery_event_levels   TEXT,
    lcuuid                  VARCHAR(64),
    biz_id                  INTEGER DEFAULT 0,
    biz_name                VARCHAR(256) DEFAULT '',
    auto_service_id_0       INTEGER DEFAULT 0,
    auto_service_type_0     INTEGER DEFAULT 0,
    auto_service_0          VARCHAR(256) DEFAULT '',
    auto_service_id_1       INTEGER DEFAULT 0,
    auto_service_type_1     INTEGER DEFAULT 0,
    auto_service_1          VARCHAR(256) DEFAULT '',
    comb_policy_lcuuids     TEXT
);
TRUNCATE TABLE alarm_policy;
COMMENT ON COLUMN alarm_policy.level IS '0.low 1.middle 2.high';
COMMENT ON COLUMN alarm_policy.state IS '0.disabled 1.enabled';
COMMENT ON COLUMN alarm_policy.app_type IS '1-system 3-indicator 4-custom_biz_service 5-comb';
COMMENT ON COLUMN alarm_policy.sub_type IS '1-指标量;20-组件状态;21-组件性能;22-自动删除;23-资源状态;24-平台信息';
COMMENT ON COLUMN alarm_policy.deleted IS '0-not deleted; 1-deleted';
COMMENT ON COLUMN alarm_policy.contrast_type IS '1.abs 2.baseline';
COMMENT ON COLUMN alarm_policy.data_level IS '1s or 1m';
COMMENT ON COLUMN alarm_policy.agg IS '0-聚合; 1-不聚合';
COMMENT ON COLUMN alarm_policy.delay IS '0-不延迟; 1-延迟';

CREATE TABLE IF NOT EXISTS alarm_event (
    id                      SERIAL PRIMARY KEY,
    status                  VARCHAR(64),
    timestamp               TIMESTAMP,
    end_time                BIGINT,
    policy_id               INTEGER,
    policy_name             TEXT,
    policy_level            INTEGER,
    policy_app_type         SMALLINT,
    policy_sub_type         SMALLINT,
    policy_contrast_type    SMALLINT,
    policy_data_level       VARCHAR(64),
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
    value_unit              VARCHAR(64),
    endpoint_results        TEXT,
    event_level             INTEGER,
    lcuuid                  VARCHAR(64)
);
TRUNCATE TABLE alarm_event;

CREATE TABLE IF NOT EXISTS report_policy (
    id                      SERIAL PRIMARY KEY,
    name                    VARCHAR(64) NOT NULL,
    view_id                 INTEGER NOT NULL,
    user_id                 INTEGER,
    data_level              VARCHAR(2) NOT NULL DEFAULT '1m' CHECK (data_level IN ('1s','1m')),
    report_format           SMALLINT DEFAULT 1,
    report_type             SMALLINT DEFAULT 1,
    interval_time           VARCHAR(2) NOT NULL DEFAULT '1h' CHECK (interval_time IN ('1d','1h')),
    state                   SMALLINT DEFAULT 1,
    push_type               SMALLINT DEFAULT 1,
    push_email              TEXT,
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    begin_at                TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lcuuid                  VARCHAR(64) NOT NULL
);
TRUNCATE TABLE report_policy;
COMMENT ON COLUMN report_policy.report_format IS 'Type of format (1-html)';
COMMENT ON COLUMN report_policy.report_type IS 'Type of reports (0-daily; 1-weekly; 2-monthly)';
COMMENT ON COLUMN report_policy.state IS '0-disable; 1-enable';
COMMENT ON COLUMN report_policy.push_type IS '1-email';
COMMENT ON COLUMN report_policy.push_email IS 'separated by ,';

CREATE TABLE IF NOT EXISTS report (
    id                      SERIAL PRIMARY KEY,
    title                   VARCHAR(200) NOT NULL DEFAULT '',
    begin_at                TIMESTAMP DEFAULT NULL,
    end_at                  TIMESTAMP DEFAULT NULL,
    policy_id               INTEGER NOT NULL DEFAULT 0 CHECK (policy_id >= 0),
    content                 TEXT,
    lcuuid                  VARCHAR(64) NOT NULL DEFAULT '',
    created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (lcuuid)
);
TRUNCATE TABLE report;
CREATE INDEX report_policy_id_index ON report (policy_id);
COMMENT ON TABLE report IS 'report records';
COMMENT ON COLUMN report.title IS 'Title of the report';
COMMENT ON COLUMN report.begin_at IS 'Start time of the report';
COMMENT ON COLUMN report.end_at IS 'End time of the report';
COMMENT ON COLUMN report.policy_id IS 'report_policy ID';

-- Prometheus
CREATE TABLE IF NOT EXISTS prometheus_metric_name (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256) NOT NULL,
    synced_at               TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (name)
);
TRUNCATE TABLE prometheus_metric_name;

CREATE TABLE IF NOT EXISTS prometheus_label_name (
    id                      INTEGER NOT NULL PRIMARY KEY,
    name                    VARCHAR(256) NOT NULL,
    synced_at               TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (name)
);
TRUNCATE TABLE prometheus_label_name;

CREATE TABLE IF NOT EXISTS prometheus_label_value (
    id                      SERIAL PRIMARY KEY,
    value                   TEXT,
    synced_at               TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE prometheus_label_value;

CREATE TABLE IF NOT EXISTS prometheus_label (
    id                      SERIAL PRIMARY KEY,
    name                    VARCHAR(256) NOT NULL,
    value                   TEXT,
    synced_at               TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
TRUNCATE TABLE prometheus_label;

CREATE TABLE IF NOT EXISTS prometheus_metric_app_label_layout (
    id                      SERIAL PRIMARY KEY,
    metric_name             VARCHAR(256) NOT NULL,
    app_label_name          VARCHAR(256) NOT NULL,
    app_label_column_index  SMALLINT NOT NULL,
    synced_at               TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (metric_name, app_label_name)
);
TRUNCATE TABLE prometheus_metric_app_label_layout;

CREATE TABLE IF NOT EXISTS prometheus_metric_label_name (
    id                      SERIAL PRIMARY KEY,
    metric_name             VARCHAR(256) NOT NULL,
    label_name_id           INTEGER NOT NULL,
    synced_at               TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (metric_name, label_name_id)
);
TRUNCATE TABLE prometheus_metric_label_name;

CREATE TABLE IF NOT EXISTS prometheus_metric_target (
    id                      SERIAL PRIMARY KEY,
    metric_name             VARCHAR(256) NOT NULL,
    target_id               INTEGER NOT NULL,
    synced_at               TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (metric_name, target_id)
);
TRUNCATE TABLE prometheus_metric_target;

CREATE TABLE IF NOT EXISTS resource_version (
    id                      SERIAL PRIMARY KEY,
    name                    VARCHAR(255) NOT NULL,
    version                 INTEGER NOT NULL DEFAULT 0,
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (name)
);
TRUNCATE TABLE resource_version;
