package metrics

import (
	"fmt"
)

var DB_FIELD_REQUEST = fmt.Sprintf(
	"if(type IN [%d, %d],1,0)", FLOW_LOG_TYPE_REQUEST, FLOW_LOG_TYPE_SESSION,
)
var DB_FIELD_RESPONSE = fmt.Sprintf(
	"if(type IN [%d, %d],1,0)", FLOW_LOG_TYPE_RESPONSE, FLOW_LOG_TYPE_SESSION,
)
var DB_FIELD_ERROR = fmt.Sprintf(
	"if(response_status IN [%d, %d],1,0)", FLOW_LOG_EXCEPTION_CLIENT, FLOW_LOG_EXCEPTION_SERVER,
)
var DB_FIELD_CLIENT_ERROR = fmt.Sprintf(
	"if(response_status IN [%d],1,0)", FLOW_LOG_EXCEPTION_CLIENT,
)
var DB_FIELD_SERVER_ERROR = fmt.Sprintf(
	"if(response_status IN [%d],1,0)", FLOW_LOG_EXCEPTION_SERVER,
)

var L7_FLOW_LOG_METRICS = map[string]*Metrics{}

var L7_FLOW_LOG_METRICS_REPLACE = map[string]*Metrics{
	"log_count":          NewReplaceMetrics("1", ""),
	"request":            NewReplaceMetrics(DB_FIELD_REQUEST, ""),
	"response":           NewReplaceMetrics(DB_FIELD_RESPONSE, ""),
	"error":              NewReplaceMetrics(DB_FIELD_ERROR, ""),
	"client_error":       NewReplaceMetrics(DB_FIELD_CLIENT_ERROR, ""),
	"server_error":       NewReplaceMetrics(DB_FIELD_SERVER_ERROR, ""),
	"error_ratio":        NewReplaceMetrics(DB_FIELD_ERROR+"/"+DB_FIELD_RESPONSE, ""),
	"client_error_ratio": NewReplaceMetrics(DB_FIELD_CLIENT_ERROR+"/"+DB_FIELD_RESPONSE, ""),
	"server_error_ratio": NewReplaceMetrics(DB_FIELD_SERVER_ERROR+"/"+DB_FIELD_RESPONSE, ""),
}

func GetL7FlowLogMetrics() map[string]*Metrics {
	// TODO: 特殊指标量修改
	return L7_FLOW_LOG_METRICS
}
