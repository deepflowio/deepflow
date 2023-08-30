package loki_exporter

import (
	"errors"
	"fmt"
	"github.com/deepflowio/deepflow/server/ingester/common"
	ingester_config "github.com/deepflowio/deepflow/server/ingester/config"
	exporter_common "github.com/deepflowio/deepflow/server/ingester/flow_log/exporter/common"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/log_data"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/utils"
	"github.com/grafana/loki-client-go/loki"
	"github.com/grafana/loki-client-go/pkg/backoff"
	"github.com/grafana/loki-client-go/pkg/labelutil"
	"github.com/grafana/loki-client-go/pkg/urlutil"
	"github.com/op/go-logging"
	"github.com/prometheus/common/model"
	"time"
)

// Loki exporter transform flow_log to plaintext log in certain format, and push to Loki via HTTP
// API `POST /loki/api/v1/push`.

const (
	// LokiQueueBatchLimit represent how many items worker could get from a queue.
	// e.g.:
	// 3000 item in queue, worker could get LokiQueueBatchLimit item at once.
	// if only 10 item in queue, worker could get all of them at once.
	LokiQueueBatchLimit = 1024
)

var log = logging.MustGetLogger("flow_log.exporter.loki_exporter")

type LokiExporter struct {
	cfg lokiExporterConfig

	// Internal Fields
	// lokiClient a loki HTTP client
	lokiClient *loki.Client
	// exportDataTypeBits represent data types to be exported.
	// e.g. "service_info", "tracing_info", "network_layer", "flow_info", "transport_layer", "application_layer", "metrics"
	exportDataTypeBits uint32
	// exportDataBits represent data to be exported.
	// e.g. "cbpf-net-span", "ebpf-sys-span".
	exportDataBits uint32

	// exportL7ProtocolMap represent protocol to be exported.
	// e.g. "
	exportL7ProtocolMap map[string]bool
	// dataQueues receive data from `Put(items ...interface{})`
	dataQueues queue.FixedMultiQueue
	// logHeaderFmt build from LogFmt, e.g.:
	// - "time=%s, service_name=%s, log_level=%s, trace_id=%s, span_id=%s, "
	// - "myTime=%s, custom_service_name_key=%s, level=%s, tid=%s, sid=%s, "
	logHeaderFmt string

	// loki exporter counter
	counter     *exporter_common.Counter
	lastCounter exporter_common.Counter

	universalTagsManager *exporter_common.UniversalTagsManager

	utils.Closable
}

type lokiExporterConfig struct {
	// URL url of loki server
	URL string
	// TenantID empty string means single tenant mode
	TenantID string
	// QueueCount queue count which queue will be processed by different goroutine
	QueueCount int
	// QueueSize represent the max item could be hold in a single queue
	QueueSize int
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
	// StaticLabels labels to add to each log
	StaticLabels model.LabelSet
	// LogFmt log format
	LogFmt LogFmt
	// ExportOnlyWithTraceID filter flow log without trace_id
	ExportOnlyWithTraceID bool
}

func (le *LokiExporter) GetCounter() interface{} {
	var counter exporter_common.Counter
	counter, *le.counter = *le.counter, exporter_common.Counter{}
	le.lastCounter = counter
	return &counter
}

func NewLokiExporter(config *LokiExporterConfig, baseCfg *ingester_config.Config) *LokiExporter {
	le := &LokiExporter{
		cfg: lokiExporterConfig{
			URL:             config.URL,
			TenantID:        config.TenantID,
			MaxMessageWait:  time.Duration(1) * time.Second,
			MaxMessageBytes: 1024 * 1024,
			Timeout:         time.Duration(3) * time.Second,
			MinBackoff:      time.Duration(500) * time.Millisecond,
			MaxBackoff:      time.Duration(5) * time.Second,
			MaxRetries:      5,
			QueueCount:      4,
			QueueSize:       1024,
		},
	}

	if config.MaxMessageWaitSecond > 0 {
		le.cfg.MaxMessageWait = time.Duration(config.MaxMessageWaitSecond) * time.Second
	}

	if config.MaxMessageBytes > 0 {
		le.cfg.MaxMessageBytes = int(config.MaxMessageBytes)
	}

	if config.TimeoutSecond > 0 {
		le.cfg.Timeout = time.Duration(config.TimeoutSecond) * time.Second
	}

	if config.MinBackoffSecond > 0 {
		le.cfg.MinBackoff = time.Duration(config.MinBackoffSecond) * time.Second
	}

	if config.MaxBackoffSecond > 0 {
		le.cfg.MaxBackoff = time.Duration(config.MaxBackoffSecond) * time.Second
	}

	if config.MaxRetries > 0 {
		le.cfg.MaxRetries = int(config.MaxRetries)
	}

	if len(config.StaticLabels) > 0 {
		labelSet := model.LabelSet{}
		for k, v := range config.StaticLabels {
			labelSet[model.LabelName(k)] = model.LabelValue(v)
		}
		le.cfg.StaticLabels = labelSet
	}

	exportDataBits := uint32(0)
	if len(config.ExportDatas) == 0 {
		config.ExportDatas = DefaultLokiExportDatas
	}
	for _, v := range config.ExportDatas {
		exportDataBits |= uint32(exporter_common.StringToExportedData(v))
	}
	le.exportDataBits = exportDataBits
	log.Infof("export data bits: %08b, string: %s", exportDataBits, exporter_common.ExportedDataBitsToString(exportDataBits))

	exportDataTypeBits := uint32(0)
	if len(config.ExportDataTypes) == 0 {
		config.ExportDatas = DefaultLokiExportDataTypes
	}
	for _, v := range config.ExportDataTypes {
		exportDataTypeBits |= uint32(exporter_common.StringToExportedDataType(v))
	}
	le.exportDataTypeBits = exportDataTypeBits

	le.buildLogHeader()

	clientCfg, err := le.buildLokiConfig()
	if err != nil {
		log.Errorf("generate loki client config err: %v", err)
		return nil
	}
	client, err := loki.New(clientCfg)
	if err != nil {
		log.Errorf("new loki client err: %v", err)
		return nil
	}
	le.lokiClient = client

	dataQueues := queue.NewOverwriteQueues(
		"loki-exporter", queue.HashKey(le.cfg.QueueCount), le.cfg.QueueSize,
		queue.OptionFlushIndicator(time.Second),
		queue.OptionRelease(func(p interface{}) { p.(exporter_common.ExportItem).Release() }),
		common.QUEUE_STATS_MODULE_INGESTER)

	le.universalTagsManager = exporter_common.NewUniversalTagsManager(".+", baseCfg.ControllerIPs, baseCfg.ControllerPort, baseCfg.GrpcBufferSize)

	le.dataQueues = dataQueues
	le.counter = &exporter_common.Counter{}
	return le
}

func (le *LokiExporter) buildLokiConfig() (loki.Config, error) {
	config := loki.Config{
		TenantID:  le.cfg.TenantID,
		BatchWait: le.cfg.MaxMessageWait,
		BatchSize: le.cfg.MaxMessageBytes,
		Timeout:   le.cfg.Timeout,
		BackoffConfig: backoff.BackoffConfig{
			MinBackoff: le.cfg.MinBackoff,
			MaxBackoff: le.cfg.MaxBackoff,
			MaxRetries: le.cfg.MaxRetries,
		},
		ExternalLabels: labelutil.LabelSet{
			LabelSet: le.cfg.StaticLabels,
		},
	}
	var url urlutil.URLValue
	err := url.Set(le.cfg.URL)
	if err != nil {
		return config, errors.New("url is invalid")
	}
	config.URL = url
	return config, nil
}

// Start starts an exporter worker
func (le *LokiExporter) Start() {
	go le.universalTagsManager.Start()
	for i := 0; i < le.cfg.QueueCount; i++ {
		go le.processQueue(i)
	}
}

func (le *LokiExporter) processQueue(queueID int) {
	defer le.stop()

	flows := make([]interface{}, LokiQueueBatchLimit)
	for {
		n := le.dataQueues.Gets(queue.HashKey(queueID), flows)
		for _, flow := range flows[:n] {
			if flow == nil {
				continue
			}

			switch t := flow.(type) {
			case *log_data.L7FlowLog:
				f := flow.(*log_data.L7FlowLog)
				timestamp := time.UnixMicro(f.EndTime().Microseconds())
				err := le.lokiClient.Handle(nil, timestamp, le.FlowLogToLog(f))
				if err != nil {
					log.Errorf("lokiClient handle log err: %v", err)
				}
				// todo the counter is not atomic without lock
				le.counter.SendCounter++
				f.Release()
			default:
				log.Warningf("flow type(%T) unsupport", t)
				continue
			}
		}
	}
}

// Put sends data to the loki exporter worker. Worker transform data to plaintext log and batch in
// buffer queue, then push it to loki via HTTP API `POST /loki/api/v1/push`
func (le *LokiExporter) Put(items ...interface{}) {
	le.counter.RecvCounter++
	if err := le.dataQueues.Put(queue.HashKey(int(le.counter.RecvCounter)%le.cfg.QueueCount), items...); err != nil {
		log.Errorf("queue put error: %v", err)
	}
}

// IsExportData tell the decoder if data need to be sended to loki exporter.
func (le *LokiExporter) IsExportData(item interface{}) bool {
	l7, ok := item.(*log_data.L7FlowLog)
	if !ok {
		return false
	}

	signalSource := datatype.SignalSource(l7.SignalSource)

	if (1<<uint32(signalSource))&le.exportDataBits == 0 {
		return false
	}
	return true
}

func (le *LokiExporter) FlowLogToLog(l7 *log_data.L7FlowLog) string {
	t := time.UnixMicro(l7.EndTime().Microseconds()) // time.Time
	serviceName := le.universalTagsManager.GetServiceName(l7)
	logLevel := responseStatusToLogLevel(l7.ResponseStatus)
	spanId := l7.SpanId

	traceId := exporter_common.GetTraceID(l7.TraceId, l7.ID()).String()
	if l7.SignalSource == uint16(datatype.SIGNAL_SOURCE_OTEL) {
		spanId = exporter_common.GetSpanID(l7.SpanId, l7.ID()).String()
	} else {
		spanId = exporter_common.Uint64ToSpanID(l7.ID()).String()
	}

	logHeader := fmt.Sprintf(le.logHeaderFmt, t, serviceName, logLevel, traceId, spanId)
	// compose log body while preserving original field names.
	var logBody string
	switch datatype.L7Protocol(l7.L7Protocol) {
	case datatype.L7_PROTOCOL_DNS:
		logBody = buildLogBodyDNS(l7)
	case datatype.L7_PROTOCOL_HTTP_1, datatype.L7_PROTOCOL_HTTP_2, datatype.L7_PROTOCOL_HTTP_1_TLS, datatype.L7_PROTOCOL_HTTP_2_TLS:
		logBody = buildLogBodyHTTP(l7)
	case datatype.L7_PROTOCOL_DUBBO:
		logBody = buildLogBodyDubbo(l7)
	case datatype.L7_PROTOCOL_GRPC:
		logBody = buildLogBodyGRPC(l7)
	case datatype.L7_PROTOCOL_KAFKA:
		logBody = buildLogBodyKafka(l7)
	case datatype.L7_PROTOCOL_MQTT:
		logBody = buildLogBodyMQTT(l7)
	case datatype.L7_PROTOCOL_MYSQL:
		logBody = buildLogBodyMySQL(l7)
	case datatype.L7_PROTOCOL_REDIS:
		logBody = buildLogBodyRedis(l7)
	case datatype.L7_PROTOCOL_POSTGRE:
		logBody = buildLogBodyPostgreSQL(l7)
	}

	return logHeader + logBody
}

// stop will be executed in defer to close resources.
func (le *LokiExporter) stop() {
	le.lokiClient.Stop()
}
