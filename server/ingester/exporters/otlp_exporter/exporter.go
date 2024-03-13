/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package otlp_exporter

import (
	"fmt"
	"strconv"
	"time"

	logging "github.com/op/go-logging"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	ingester_common "github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/exporters/common"
	exporters_cfg "github.com/deepflowio/deepflow/server/ingester/exporters/config"
	utag "github.com/deepflowio/deepflow/server/ingester/exporters/universal_tag"
	"github.com/deepflowio/deepflow/server/ingester/ingesterctl"
	"github.com/deepflowio/deepflow/server/libs/debug"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

var log = logging.MustGetLogger("otlp_exporter")

const (
	QUEUE_BATCH_COUNT = 1024
)

type OtlpExporter struct {
	index                int
	Addr                 string
	dataQueues           queue.FixedMultiQueue
	queueCount           int
	grpcExporters        []ptraceotlp.GRPCClient
	grpcConns            []*grpc.ClientConn
	universalTagsManager *utag.UniversalTagsManager
	config               *exporters_cfg.ExporterCfg
	counter              *Counter
	lastCounter          Counter
	running              bool

	utils.Closable
}

type Counter struct {
	RecvCounter          int64 `statsd:"recv-count"`
	SendCounter          int64 `statsd:"send-count"`
	SendBatchCounter     int64 `statsd:"send-batch-count"`
	ExportUsedTimeNs     int64 `statsd:"export-used-time-ns"`
	DropCounter          int64 `statsd:"drop-count"`
	DropBatchCounter     int64 `statsd:"drop-batch-count"`
	DropNoTraceIDCounter int64 `statsd:"drop-no-traceid-count"`
}

func (e *OtlpExporter) GetCounter() interface{} {
	var counter Counter
	counter, *e.counter = *e.counter, Counter{}
	e.lastCounter = counter
	return &counter
}

func NewOtlpExporter(index int, config *exporters_cfg.ExporterCfg, universalTagsManager *utag.UniversalTagsManager) *OtlpExporter {
	otlpConfig := config

	dataQueues := queue.NewOverwriteQueues(
		fmt.Sprintf("otlp_exporter_%d", index), queue.HashKey(otlpConfig.QueueCount), otlpConfig.QueueSize,
		queue.OptionFlushIndicator(time.Second),
		queue.OptionRelease(func(p interface{}) { p.(common.ExportItem).Release() }),
		ingester_common.QUEUE_STATS_MODULE_INGESTER)

	exporter := &OtlpExporter{
		index:                index,
		dataQueues:           dataQueues,
		queueCount:           otlpConfig.QueueCount,
		universalTagsManager: universalTagsManager,
		grpcConns:            make([]*grpc.ClientConn, otlpConfig.QueueCount),
		grpcExporters:        make([]ptraceotlp.GRPCClient, otlpConfig.QueueCount),
		config:               otlpConfig,
		counter:              &Counter{},
	}
	debug.ServerRegisterSimple(ingesterctl.CMD_OTLP_EXPORTER, exporter)
	ingester_common.RegisterCountableForIngester("exporter", exporter, stats.OptionStatTags{
		"type": "otlp", "index": strconv.Itoa(index)})
	log.Infof("otlp exporter %d created", index)
	return exporter
}

/*
func (e *OtlpExporter) IsExportData(item common.ExportItem, cfg *config.ExporterCfg) bool { // l *log_data.L7FlowLog) bool {
	/*
		if e.config.ExportOnlyWithTraceID != nil && *e.config.ExportOnlyWithTraceID && l.TraceId == "" {
			return false
		}
		if (1<<uint32(l.SignalSource))&e.config.ExportDataBits == 0 {
			return false
		}

		// always not export data from OTel
		if l.SignalSource == uint16(datatype.SIGNAL_SOURCE_OTEL) {
			e.counter.DropCounter++
			return false
		}
	return true
}
*/

func (e *OtlpExporter) Put(items ...interface{}) {
	e.counter.RecvCounter++
	e.dataQueues.Put(queue.HashKey(int(e.counter.RecvCounter)%e.queueCount), items...)
}

func (e *OtlpExporter) Start() {
	if e.running {
		log.Warningf("otlp exporter %d already running", e.index)
		return
	}
	e.running = true
	for i := 0; i < e.queueCount; i++ {
		go e.queueProcess(int(i))
	}
	log.Infof("otlp exporter %d started %d queue", e.index, e.queueCount)
}

func (e *OtlpExporter) Close() {
	e.running = false
	log.Infof("otlp exporter %d stopping", e.index)
}

func (e *OtlpExporter) queueProcess(queueID int) {
	var batchCount int
	traces := ptrace.NewTraces()
	items := make([]interface{}, QUEUE_BATCH_COUNT)

	ctx := context.Background()
	if len(e.config.ExtraHeaders) > 0 {
		ctx = metadata.NewOutgoingContext(ctx, metadata.New(e.config.ExtraHeaders))
	}
	for e.running {
		n := e.dataQueues.Gets(queue.HashKey(queueID), items)
		for _, item := range items[:n] {
			if item == nil {
				if batchCount > 0 {
					if err := e.grpcExport(ctx, queueID, ptraceotlp.NewExportRequestFromTraces(traces)); err == nil {
						e.counter.SendCounter += int64(batchCount)
					}
					batchCount = 0
					traces = ptrace.NewTraces()
				}
				continue
			}
			exportItem, ok := item.(common.ExportItem)
			if !ok {
				continue
			}

			dst, err := exportItem.EncodeTo(exporters_cfg.PROTOCOL_OTLP, e.universalTagsManager, e.config)
			if err != nil {
				continue
			}
			rsSlice := dst.(ptrace.ResourceSpansSlice)
			rsSlice.MoveAndAppendTo(traces.ResourceSpans())
			// encode := encoded.(ptrace.ResourceSpan)
			// L7FlowLogToExportResourceSpans(f, e.universalTagsManager, 0, traces.ResourceSpans().AppendEmpty())
			batchCount++
			if batchCount >= e.config.BatchSize {
				if err := e.grpcExport(ctx, queueID, ptraceotlp.NewExportRequestFromTraces(traces)); err == nil {
					e.counter.SendCounter += int64(batchCount)
				}
				batchCount = 0
				traces = ptrace.NewTraces()
			}
			exportItem.Release()
		}
	}
}

func (e *OtlpExporter) grpcExport(ctx context.Context, i int, req ptraceotlp.ExportRequest) error {
	defer func() {
		if r := recover(); r != nil {
			log.Warningf("otlp grpc export error: %s", r)
			if j, err := req.MarshalJSON(); err == nil {
				log.Infof("otlp request: %s", string(j))
			}
		}
	}()

	now := time.Now()

	if e.grpcExporters[i] == nil {
		if err := e.newGrpcExporter(i); err != nil {
			if e.counter.DropCounter == 0 {
				log.Warningf("new grpc exporter failed. err: %s", err)
			}
			e.counter.DropCounter++
			return err
		}
	}
	_, err := e.grpcExporters[i].Export(ctx, req)
	if err != nil {
		if e.counter.DropCounter == 0 {
			log.Warningf("exporter %d send grpc traces failed. err: %s", e.index, err)
		}
		e.counter.DropCounter++
		e.grpcExporters[i] = nil
		return err
	} else {
		e.counter.SendBatchCounter++
	}
	e.counter.ExportUsedTimeNs += int64(time.Since(now))
	return nil
}

func (e *OtlpExporter) newGrpcExporter(i int) error {
	if e.grpcConns[i] != nil {
		e.grpcConns[i].Close()
		e.grpcConns[i] = nil
	}
	var options = []grpc.DialOption{grpc.WithInsecure(), grpc.WithTimeout(time.Minute)}
	conn, err := grpc.Dial(e.config.Endpoints[0], options...)
	if err != nil {
		return fmt.Errorf("grpc dial %s failed, err: %s", e.config.Endpoints[0], err)
	}
	log.Debugf("new grpc otlp exporter: %s", e.config.Endpoints[0])
	e.grpcConns[i] = conn
	e.grpcExporters[i] = ptraceotlp.NewGRPCClient(conn)
	return nil
}

func (e *OtlpExporter) HandleSimpleCommand(op uint16, arg string) string {
	return fmt.Sprintf("otlp exporter %d last 10s counter: %+v", e.index, e.lastCounter)
}
