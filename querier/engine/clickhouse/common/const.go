package common

const PERMISSION_TYPE_NUM = 3

var DB_TABLE_MAP = map[string][]string{
	"flow_log":            []string{"l4_flow_log", "l7_flow_log"},
	"vtap_flow_port":      []string{"1m"},
	"vtap_flow_edge_port": []string{"1m"},
}
