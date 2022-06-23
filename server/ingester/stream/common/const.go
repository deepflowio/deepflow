package common

const (
	FLOW_LOG_DB = "flow_log"
)

type FlowLogID uint8

const (
	L4_FLOW_ID FlowLogID = iota
	L7_FLOW_ID

	FLOWLOG_ID_MAX
)

var flowLogNames = []string{
	L4_FLOW_ID: "l4_flow_log",
	L7_FLOW_ID: "l7_flow_log",
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
