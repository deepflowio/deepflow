package metrics

var FILE_AGG_EVENT_METRICS = map[string]*Metrics{}
var FILE_AGG_EVENT_METRICS_REPLACE = map[string]*Metrics{
	"log_count": NewReplaceMetrics("1", ""),
}

var FILE_MGMT_EVENT_METRICS = map[string]*Metrics{}
var FILE_MGMT_EVENT_METRICS_REPLACE = map[string]*Metrics{
	"log_count": NewReplaceMetrics("1", ""),
}

var PROC_PERM_EVENT_METRICS = map[string]*Metrics{}
var PROC_PERM_EVENT_METRICS_REPLACE = map[string]*Metrics{
	"log_count": NewReplaceMetrics("1", ""),
}

var PROC_OPS_EVENT_METRICS = map[string]*Metrics{}
var PROC_OPS_EVENT_METRICS_REPLACE = map[string]*Metrics{
	"log_count": NewReplaceMetrics("1", ""),
}
