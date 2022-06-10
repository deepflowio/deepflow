package common

const PERMISSION_TYPE_NUM = 3

var DB_TABLE_MAP = map[string][]string{
	"flow_log":     []string{"l4_flow_log", "l7_flow_log"},
	"flow_metrics": []string{"vtap_flow_port", "vtap_flow_edge_port", "vtap_app_port", "vtap_app_edge_port"},
}
