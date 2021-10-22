package common

const (
	FLOW_LOG_DB = "flow_log"
)

type FlowLogID uint8

const (
	L4_FLOW_ID FlowLogID = iota
	L7_HTTP_ID
	L7_DNS_ID
	L7_SQL_ID
	L7_NOSQL_ID
	L7_RPC_ID
	L7_MQ_ID

	FLOWLOG_ID_MAX
)

var flowLogNames = []string{
	L4_FLOW_ID:  "l4_flow_log",
	L7_HTTP_ID:  "l7_http_log",
	L7_DNS_ID:   "l7_dns_log",
	L7_SQL_ID:   "l7_sql_log",
	L7_NOSQL_ID: "l7_nosql_log",
	L7_RPC_ID:   "l7_rpc_log",
	L7_MQ_ID:    "l7_mq_log",
}

func (l FlowLogID) String() string {
	return flowLogNames[l]
}

func (l FlowLogID) TimeKey() string {
	return "time"
}

func FlowLogNameToID(name string) FlowLogID {
	for i, n := range flowLogNames {
		if name == n {
			return FlowLogID(i)
		}
	}

	return FLOWLOG_ID_MAX
}
