package exporter

import (
	"fmt"
	"time"

	logging "github.com/op/go-logging"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/config"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/log_data"
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

	traceIDs []pcommon.TraceID
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
	}
	common.RegisterCountableForIngester("exporter", &exporter.counter)
	log.Info("otlp exporter start")
	exporter.traceIDs = make([]pcommon.TraceID, exportConfig.QueueCount)
	return exporter
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
	req := L7FlowLogToExportRequest(f, e.universalTagsManager)
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
	log.Infof("new grpc otlp exporter: %s", config.Addr)
	e.grpcConns[i] = conn
	e.grpcExporters[i] = ptraceotlp.NewGRPCClient(conn)
	return nil
}
