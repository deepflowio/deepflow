package exporter

import (
	"fmt"
	"time"

	logging "github.com/op/go-logging"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/config"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/log_data"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

var log = logging.MustGetLogger("flow_log.exporter")

type OtlpExporter struct {
	Addr                 string
	dataQueues           queue.FixedMultiQueue
	queueCount           int
	grpcExporters        []ptraceotlp.GRPCClient
	grpcConns            []*grpc.ClientConn
	universalTagsManager *UniversalTagsManager
	config               *config.Config
	counter              Counter
	exportDataBits       uint32
	exportDataTypeBits   uint32
}

const (
	UNKNOWN_DATA  = 0
	CBPF_NET_SPAN = uint32(1 << datatype.SIGNAL_SOURCE_PACKET)
	EBPF_SYS_SPAN = uint32(1 << datatype.SIGNAL_SOURCE_EBPF)
	OTEL_APP_SPAN = uint32(1 << datatype.SIGNAL_SOURCE_OTEL)
)

var exportedDataStringMap = map[string]uint32{
	"cbpf-net-span": CBPF_NET_SPAN,
	"ebpf-sys-span": EBPF_SYS_SPAN,
	"otel-app-span": OTEL_APP_SPAN,
}

func bitsToString(bits uint32, strMap map[string]uint32) string {
	ret := ""
	for k, v := range strMap {
		if bits&v != 0 {
			if len(ret) == 0 {
				ret = k
			} else {
				ret = ret + "," + k
			}
		}
	}
	return ret
}

func ExportedDataBitsToString(bits uint32) string {
	return bitsToString(bits, exportedDataStringMap)
}

func StringToExportedData(str string) uint32 {
	t, ok := exportedDataStringMap[str]
	if !ok {
		log.Warningf("unknown exporter data: %s", str)
		return UNKNOWN_DATA
	}
	return t
}

const (
	UNKNOWN_DATA_TYPE = 0

	SERVICE_INFO uint32 = 1 << iota
	TRACING_INFO
	NETWORK_LAYER
	FLOW_INFO
	CLIENT_UNIVERSAL_TAG
	SERVER_UNIVERSAL_TAG
	TUNNEL_INFO
	TRANSPORT_LAYER
	APPLICATION_LAYER
	CAPTURE_INFO
	CLIENT_CUSTOM_TAG
	SERVER_CUSTOM_TAG
	NATIVE_TAG
	METRICS
)

var exportedDataTypeStringMap = map[string]uint32{
	"service_info":         SERVICE_INFO,
	"tracing_info":         TRACING_INFO,
	"network_layer":        NETWORK_LAYER,
	"flow_info":            FLOW_INFO,
	"client_universal_tag": CLIENT_UNIVERSAL_TAG,
	"server_universal_tag": SERVER_UNIVERSAL_TAG,
	"tunnel_info":          TUNNEL_INFO,
	"transport_layer":      TRANSPORT_LAYER,
	"application_layer":    APPLICATION_LAYER,
	"capture_info":         CAPTURE_INFO,
	"client_custom_tag":    CLIENT_CUSTOM_TAG,
	"server_custom_tag":    SERVER_CUSTOM_TAG,
	"native_tag":           NATIVE_TAG,
	"metrics":              METRICS,
}

func StringToExportedDataType(str string) uint32 {
	t, ok := exportedDataTypeStringMap[str]
	if !ok {
		log.Warningf("unknown exporter data type: %s", str)
		return UNKNOWN_DATA_TYPE
	}
	return t
}

func ExportedDataTypeBitsToString(bits uint32) string {
	return bitsToString(bits, exportedDataTypeStringMap)
}

type Counter struct {
	RecvCounter int64 `statsd:"recv-count"`
	SendCounter int64 `statsd:"send-count"`
	DropCounter int64 `statsd:"drop-count"`
	utils.Closable
}

func (c *Counter) GetCounter() interface{} {
	var counter Counter
	counter, *c = *c, Counter{}

	return &counter
}

type ExportItem interface {
	Release()
}

func NewOtlpExporter(config *config.Config) *OtlpExporter {
	exportConfig := &config.Exporter
	if !exportConfig.Enabled {
		log.Info("otlp exporter disabled")
		return nil
	}
	exportDataBits := uint32(0)
	for _, v := range config.Exporter.ExportDatas {
		exportDataBits |= uint32(StringToExportedData(v))
	}
	log.Infof("export data bits: %08b, string: %s", exportDataBits, ExportedDataBitsToString(exportDataBits))

	exportDataTypeBits := uint32(0)
	for _, v := range config.Exporter.ExportDataTypes {
		exportDataTypeBits |= uint32(StringToExportedDataType(v))
	}
	log.Infof("export data type bits: %08b, string: %s", exportDataTypeBits, ExportedDataTypeBitsToString(exportDataTypeBits))

	dataQueues := queue.NewOverwriteQueues(
		"exporter", queue.HashKey(exportConfig.QueueCount), exportConfig.QueueSize,
		queue.OptionFlushIndicator(time.Second),
		queue.OptionRelease(func(p interface{}) { p.(ExportItem).Release() }),
		common.QUEUE_STATS_MODULE_INGESTER)

	universalTagsManager := NewUniversalTagsManager(config)
	exporter := &OtlpExporter{
		dataQueues:           dataQueues,
		queueCount:           exportConfig.QueueCount,
		universalTagsManager: universalTagsManager,
		grpcConns:            make([]*grpc.ClientConn, exportConfig.QueueCount),
		grpcExporters:        make([]ptraceotlp.GRPCClient, exportConfig.QueueCount),
		config:               config,
		exportDataBits:       exportDataBits,
		exportDataTypeBits:   exportDataTypeBits,
	}
	common.RegisterCountableForIngester("exporter", &exporter.counter)
	log.Info("otlp exporter start")
	return exporter
}

func (e *OtlpExporter) IsExportData(signalSource datatype.SignalSource) bool {
	return (1<<uint32(signalSource))&e.exportDataBits != 0
}

func (e *OtlpExporter) Put(items ...interface{}) {
	e.counter.RecvCounter++
	e.dataQueues.Put(queue.HashKey(int(e.counter.RecvCounter)%e.queueCount), items...)
}

func (e *OtlpExporter) Start() {
	go e.universalTagsManager.Start()
	for i := 0; i < e.queueCount; i++ {
		go e.queueProcess(int(i))
	}
}

func (e *OtlpExporter) queueProcess(queueID int) {
	flows := make([]interface{}, 1024)
	for {
		n := e.dataQueues.Gets(queue.HashKey(queueID), flows)
		for _, flow := range flows[:n] {
			if flow == nil {
				continue
			}
			switch t := flow.(type) {
			case (*log_data.L7FlowLog):
				f := flow.(*log_data.L7FlowLog)
				e.grpcExport(queueID, f)
				f.Release()
			default:
				log.Warningf("flow type(%T) unsupport", t)
				continue
			}
		}
	}
}

func (e *OtlpExporter) grpcExport(i int, f *log_data.L7FlowLog) {
	req := L7FlowLogToExportRequest(f, e.universalTagsManager, e.exportDataTypeBits)
	if e.grpcExporters[i] == nil {
		if err := e.newGrpcExporter(i); err != nil {
			if e.counter.DropCounter == 0 {
				log.Warning("new grpc exporter failed. err: %s", err)
			}
			e.counter.DropCounter++
			return
		}
	}
	_, err := e.grpcExporters[i].Export(context.Background(), req)
	if err != nil {
		if e.counter.DropCounter == 0 {
			log.Warning("send grpc traces failed. err: %s", err)
		}
		e.counter.DropCounter++
		e.grpcExporters[i] = nil
	} else {
		e.counter.SendCounter++
	}
}

func (e *OtlpExporter) newGrpcExporter(i int) error {
	if e.grpcConns[i] != nil {
		e.grpcConns[i].Close()
		e.grpcConns[i] = nil
	}
	config := &e.config.Exporter
	var options = []grpc.DialOption{grpc.WithInsecure(), grpc.WithTimeout(time.Minute)}
	conn, err := grpc.Dial(config.Addr, options...)
	if err != nil {
		return fmt.Errorf("grpc dial %s failed, err: %s", config.Addr, err)
	}
	log.Debugf("new grpc otlp exporter: %s", config.Addr)
	e.grpcConns[i] = conn
	e.grpcExporters[i] = ptraceotlp.NewGRPCClient(conn)
	return nil
}
