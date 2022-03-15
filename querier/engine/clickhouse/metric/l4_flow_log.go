package metric

var L4_FLOW_LOG_METRICS = map[string]*Metric{
	"byte":    NewMetric("byte", "字节", "字节", METRIC_TYPE_COUNTER, L4_FLOW_LOG_CATEGORY_L3_TRAFFIC),
	"byte_tx": NewMetric("byte_tx", "发送字节", "字节", METRIC_TYPE_COUNTER, L4_FLOW_LOG_CATEGORY_L3_TRAFFIC),
	"byte_rx": NewMetric("byte_rx", "接收字节", "字节", METRIC_TYPE_COUNTER, L4_FLOW_LOG_CATEGORY_L3_TRAFFIC),
	"rtt_max": NewMetric("rtt", "最大TCP建连时延", "微秒", METRIC_TYPE_DELAY, L4_FLOW_LOG_CATEGORY_L4_LATENCY),
}
