package metrics

var VTAP_APP_PORT_METRICS = map[string]*Metrics{}

var VTAP_APP_PORT_METRICS_REPLACE = map[string]*Metrics{
	"rrt": NewReplaceMetrics("rrt_sum/rrt_count", ""),

	"error_ratio":        NewReplaceMetrics("error/response", ""),
	"client_error_ratio": NewReplaceMetrics("client_error/response", ""),
	"server_error_ratio": NewReplaceMetrics("server_error/response", ""),
}

func GetVtapAppPortMetrics() map[string]*Metrics {
	// TODO: 特殊指标量修改
	return VTAP_APP_PORT_METRICS
}
