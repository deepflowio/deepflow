pub const MYSQL_COMMAND_STRS: [&str; 32] = [
    "COM_SLEEP",
    "COM_QUIT",
    "COM_INIT_DB",
    "COM_QUERY",
    "COM_FIELD_LIST",
    "COM_CREATE_DB",
    "COM_DROP_DB",
    "COM_REFRESH",
    "COM_SHUTDOWN",
    "COM_STATISTICS",
    "COM_PROCESS_INFO",
    "COM_CONNECT",
    "COM_PROCESS_KILL",
    "COM_DEBUG",
    "COM_PING",
    "COM_TIME",
    "COM_DELAYED_INSERT",
    "COM_CHANGE_USER",
    "COM_BINLOG_DUMP",
    "COM_TABLE_DUMP",
    "COM_CONNECT_OUT",
    "COM_REGISTER_SLAVE",
    "COM_STMT_PREPARE",
    "COM_STMT_EXECUTE",
    "COM_STMT_SEND_LONG_DATA",
    "COM_STMT_CLOSE",
    "COM_STMT_RESET",
    "COM_SET_OPTION",
    "COM_STMT_FETCH",
    "COM_DAEMON",
    "COM_BINLOG_DUMP_GTID",
    "COM_RESET_CONNECTION",
];

const REQ_STR_Q: &'static str = "simple query";
const REQ_STR_P: &'static str = "parse";
const REQ_STR_B: &'static str = "bind";
const REQ_STR_E: &'static str = "execute";
const REQ_STR_F: &'static str = "fastpath function call";
const REQ_STR_C: &'static str = "close";
const REQ_STR_D: &'static str = "describe";
const REQ_STR_H: &'static str = "flush";
const REQ_STR_S: &'static str = "sync";
const REQ_STR_X: &'static str = "exit";
const REQ_STR_COPY_DATA: &'static str = "copy data";
const REQ_STR_COPY_DONE: &'static str = "copy done";
const REQ_STR_COPY_FAIL: &'static str = "copy fail";

pub(super) fn get_request_str(typ: char) -> &'static str {
    match typ {
        'Q' => REQ_STR_Q,
        'P' => REQ_STR_P,
        'B' => REQ_STR_B,
        'E' => REQ_STR_E,
        'F' => REQ_STR_F,
        'C' => REQ_STR_C,
        'D' => REQ_STR_D,
        'H' => REQ_STR_H,
        'S' => REQ_STR_S,
        'X' => REQ_STR_X,
        'd' => REQ_STR_COPY_DATA,
        'c' => REQ_STR_COPY_DONE,
        'f' => REQ_STR_COPY_FAIL,
        _ => "",
    }
}

pub const KAFKA_COMMANDS_STRS: [&str; 59] = [
    "Produce",
    "Fetch",
    "ListOffsets",
    "Metadata",
    "LeaderAndIsr",
    "StopReplica",
    "UpdateMetadata",
    "ControlledShutdown",
    "OffsetCommit",
    "OffsetFetch",
    // 10
    "FindCoordinator",
    "JoinGroup",
    "Heartbeat",
    "LeaveGroup",
    "SyncGroup",
    "DescribeGroups",
    "ListGroups",
    "SaslHandshake",
    "ApiVersions",
    "CreateTopics",
    // 20
    "DeleteTopics",
    "DeleteRecords",
    "InitProducerId",
    "OffsetForLeaderEpoch",
    "AddPartitionsToTxn",
    "AddOffsetsToTxn",
    "EndTxn",
    "WriteTxnMarkers",
    "TxnOffsetCommit",
    "DescribeAcls",
    // 30
    "CreateAcls",
    "DeleteAcls",
    "DescribeConfigs",
    "AlterConfigs",
    "AlterReplicaLogDirs",
    "DescribeLogDirs",
    "SaslAuthenticate",
    "CreatePartitions",
    "CreateDelegationToken",
    "RenewDelegationToken",
    // 40
    "ExpireDelegationToken",
    "DescribeDelegationToken",
    "DeleteGroups",
    "ElectLeaders",
    "IncrementalAlterConfigs",
    "AlterPartitionReassignments",
    "ListPartitionReassignments",
    "OffsetDelete",
    "DescribeClientQuotas",
    "AlterClientQuotas",
    //50
    "DescribeUserScramCredentials",
    "AlterUserScramCredentials",
    "AlterIsr",
    "UpdateFeatures",
    "DescribeCluster",
    "DescribeProducers",
    "DescribeTransactions",
    "ListTransactions",
    "AllocateProducerIds",
];

const DNS_DOMAIN_STRS: [&str; 17] = [
    "", "A", "NS", "MD", "MF", "CNAME", "SOA", "MB", "MG", "MR", "NULL", "WKS", "PTR", "HINFO",
    "MINFO", "MX", "TXT",
];
pub(super) fn get_domain_str(domain_type: usize) -> &'static str {
    match domain_type {
        1..=16 => DNS_DOMAIN_STRS[domain_type],
        28 => "AAAA",
        252 => "AXFR",
        253 => "MAILB",
        254 => "MAILA",
        255 => "ANY",
        _ => "",
    }
}
