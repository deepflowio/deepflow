package loki_exporter

import (
	"errors"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/exporter"
	"github.com/grafana/loki-client-go/loki"
	"github.com/grafana/loki-client-go/pkg/backoff"
	"github.com/grafana/loki-client-go/pkg/labelutil"
	"github.com/grafana/loki-client-go/pkg/urlutil"
	promconf "github.com/prometheus/common/config"
	"github.com/prometheus/common/model"
	"time"
)

// Loki exporter transform flow_log to plaintext log in certain format, and push to Loki via HTTP
// API `POST /loki/api/v1/push`.

type lokiExporter struct {
	// URL url of loki server
	URL string
	// TenantID empty string means single tenant mode
	TenantID string
	// MaxMessageWait maximum wait period before sending batch of message
	MaxMessageWait time.Duration
	// MaxMessageBytes maximum batch size of message to accrue before sending
	MaxMessageBytes int
	// Timeout maximum time to wait for server to respond
	Timeout time.Duration
	// MinBackoff minimum backoff time between retries
	MinBackoff time.Duration
	// MaxBackoff maximum backoff time between retries
	MaxBackoff time.Duration
	// MaxRetries maximum number of retries when sending batches
	MaxRetries int
	// DynamicLabels labels to be parsed from logs
	DynamicLabels []string
	// StaticLabels labels to add to each log
	StaticLabels model.LabelSet
	// ClientConfig http client config
	ClientConfig promconf.HTTPClientConfig

	// Internal Fields
	// lokiClient a loki HTTP client
	lokiClient *loki.Client
	// exportDataTypeBits represent data types to be exported.
	// e.g. "service_info", "tracing_info", "network_layer", "flow_info", "transport_layer", "application_layer", "metrics"
	exportDataTypeBits uint32
	// exportDataBits represent data to be exported.
	// e.g. "cbpf-net-span", "ebpf-sys-span".
	exportDataBits uint32
}

func NewLokiExporter(config *LokiExporterConfig) exporter.Exporter {
	return &lokiExporter{
		URL:             "",
		TenantID:        "",
		MaxMessageWait:  time.Duration(1) * time.Second,
		MaxMessageBytes: 1024 * 1024,
		Timeout:         time.Duration(10) * time.Second,
		MinBackoff:      time.Duration(500) * time.Millisecond,
		MaxBackoff:      time.Duration(5) * time.Minute,
		MaxRetries:      10,
		StaticLabels:    model.LabelSet{},
	}
}

func (f *lokiExporter) buildLokiConfig() (loki.Config, error) {
	config := loki.Config{
		TenantID:  f.TenantID,
		BatchWait: f.MaxMessageWait,
		BatchSize: f.MaxMessageBytes,
		Timeout:   f.Timeout,
		BackoffConfig: backoff.BackoffConfig{
			MinBackoff: f.MinBackoff,
			MaxBackoff: f.MaxBackoff,
			MaxRetries: f.MaxRetries,
		},
		ExternalLabels: labelutil.LabelSet{
			LabelSet: f.StaticLabels,
		},
	}
	var url urlutil.URLValue
	err := url.Set(f.URL)
	if err != nil {
		return config, errors.New("url is invalid")
	}
	config.URL = url
	return config, nil
}

// Start starts an exporter worker
func (le *lokiExporter) Start() {
	config, err := le.buildLokiConfig()
	if err != nil {
		return
	}
	client, err := loki.New(config)
	if err != nil {
		return
	}
	le.lokiClient = client
}

// Put sends data to the loki exporter worker. Worker transform data to plaintext log and batch in
// buffer queue, then push it to loki via HTTP API `POST /loki/api/v1/push`
func (le *lokiExporter) Put(items ...interface{}) {

}

// IsExportData tell the decoder if data need to be sended to loki exporter.
func (le *lokiExporter) IsExportData(items interface{}) bool {
	return false
}
