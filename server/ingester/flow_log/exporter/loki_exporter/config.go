package loki_exporter

import (
	"errors"
)

type LokiExporterConfig struct {
	// URL url of loki server
	URL string `yaml:"url"`
	// TenantID empty string means single tenant mode
	TenantID string `yaml:"tenant-id"`
	// QueueCount queue count which queue will be processed by different goroutine
	QueueCount int64 `yaml:"queue-count"`
	// QueueSize represent the max item could be hold in a single queue
	QueueSize int64 `yaml:"queue-size"`
	// MaxMessageWaitSecond maximum wait period before sending batch of message
	MaxMessageWaitSecond int64 `yaml:"max-message-wait-second"`
	// MaxMessageBytes maximum batch size of message to accrue before sending
	MaxMessageBytes int64 `yaml:"max-message-bytes"`
	// TimeoutSecond maximum time to wait for server to respond
	TimeoutSecond int64 `yaml:"timeout-second"`
	// MinBackoffSecond minimum backoff time between retries
	MinBackoffSecond int64 `yaml:"min-backoff-second"`
	// MaxBackoffSecond maximum backoff time between retries
	MaxBackoffSecond int64 `yaml:"max-backoff-second"`
	// MaxRetries maximum number of retries when sending batches
	MaxRetries int64 `yaml:"max-retries"`
	// StaticLabels labels to add to each log
	StaticLabels map[string]string `yaml:"static-labels"`
	// ExportDatas export data enums, e.g.: "cbpf-net-span", "ebpf-sys-span"
	ExportDatas []string `yaml:"export-datas"`
	// ExportDataTypes export data type enums,
	// e.g.: "service_info", "tracing_info", "network_layer", "flow_info", "transport_layer", "application_layer", "metrics"
	// todo ExportDataTypes is not implemented now.
	//ExportDataTypes []string `yaml:"export-data-types"`
	// ExportOnlyWithTraceID filter flow log without trace_id
	ExportOnlyWithTraceID bool `yaml:"export-only-with-traceid"`
	// Log format
	LogFmt LogFmt `yaml:"log-format"`
}

type LogFmt struct {
	// Mapping set alias for default log header field names.
	Mapping map[string]string `yaml:"mapping"`
}

var DefaultLokiExportDatas = []string{"cbpf-net-span", "ebpf-sys-span"}

//var DefaultLokiExportDataTypes = []string{"service_info", "tracing_info", "network_layer", "flow_info", "transport_layer", "application_layer", "metrics"}

func Validate(cfg LokiExporterConfig) error {
	if cfg.URL == "" {
		return errors.New("url is nil")
	}
	if cfg.MaxMessageBytes <= 0 {
		return errors.New("batch size is required > 0")
	}
	if len(cfg.StaticLabels) == 0 {
		return errors.New("at least one label should be set")
	}
	return nil
}
