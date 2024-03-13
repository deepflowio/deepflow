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
	"strings"
	"time"

	logging "github.com/op/go-logging"
	"go.opentelemetry.io/collector/pdata/pcommon"
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
	grpcFailedCounters   []int
	universalTagsManager *utag.UniversalTagsManager
	config               *exporters_cfg.ExporterCfg
	counter              *Counter
	lastCounter          Counter
	running              bool

	utils.Closable
}

type Counter struct {
	RecvCounter      int64 `statsd:"recv-count"`
	SendCounter      int64 `statsd:"send-count"`
	SendBatchCounter int64 `statsd:"send-batch-count"`
	ExportUsedTimeNs int64 `statsd:"export-used-time-ns"`
	DropCounter      int64 `statsd:"drop-count"`
	DropBatchCounter int64 `statsd:"drop-batch-count"`
}

func (e *OtlpExporter) GetCounter() interface{} {
	var counter Counter
	counter, *e.counter = *e.counter, Counter{}
	e.lastCounter = counter
	return &counter
}

func NewOtlpExporter(index int, config *exporters_cfg.ExporterCfg, universalTagsManager *utag.UniversalTagsManager) *OtlpExporter {
	dataQueues := queue.NewOverwriteQueues(
		fmt.Sprintf("otlp_exporter_%d", index), queue.HashKey(config.QueueCount), config.QueueSize,
		queue.OptionFlushIndicator(time.Second),
		queue.OptionRelease(func(p interface{}) { p.(common.ExportItem).Release() }),
		ingester_common.QUEUE_STATS_MODULE_INGESTER)

	exporter := &OtlpExporter{
		index:                index,
		dataQueues:           dataQueues,
		queueCount:           config.QueueCount,
		universalTagsManager: universalTagsManager,
		grpcConns:            make([]*grpc.ClientConn, config.QueueCount),
		grpcFailedCounters:   make([]int, config.QueueCount),
		grpcExporters:        make([]ptraceotlp.GRPCClient, config.QueueCount),
		config:               config,
		counter:              &Counter{},
	}
	debug.ServerRegisterSimple(ingesterctl.CMD_OTLP_EXPORTER, exporter)
	ingester_common.RegisterCountableForIngester("exporter", exporter, stats.OptionStatTags{
		"type": "otlp", "index": strconv.Itoa(index)})
	log.Infof("otlp exporter %d created", index)
	return exporter
}

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

	doExport := func() {
		if batchCount == 0 {
			return
		}

		if err := e.grpcExport(ctx, queueID, ptraceotlp.NewExportRequestFromTraces(traces)); err == nil {
			e.counter.SendCounter += int64(batchCount)
		}
		batchCount = 0
		log.Debugf(tracesToString(traces))
		traces = ptrace.NewTraces()
	}

	for e.running {
		n := e.dataQueues.Gets(queue.HashKey(queueID), items)
		for _, item := range items[:n] {
			if item == nil {
				doExport()
				continue
			}

			exportItem, ok := item.(common.ExportItem)
			if !ok {
				e.counter.DropCounter++
				continue
			}

			dst, err := exportItem.EncodeTo(exporters_cfg.PROTOCOL_OTLP, e.universalTagsManager, e.config)
			if err != nil {
				if e.counter.DropCounter == 0 {
					log.Warningf("otlp exporter encode faild. err: %s", err)
				}
				e.counter.DropCounter++
				exportItem.Release()
				continue
			}
			rsSlice := dst.(ptrace.ResourceSpansSlice)
			rsSlice.MoveAndAppendTo(traces.ResourceSpans())

			batchCount++
			if batchCount >= e.config.BatchSize {
				doExport()
			}
			exportItem.Release()
		}
	}
}

func (e *OtlpExporter) grpcExport(ctx context.Context, queueID int, req ptraceotlp.ExportRequest) error {
	defer func() {
		if r := recover(); r != nil {
			log.Warningf("grpc otlp export error: %s", r)
			if j, err := req.MarshalJSON(); err == nil {
				log.Infof("otlp request: %s", string(j))
			}
		}
	}()

	now := time.Now()

	if e.grpcExporters[queueID] == nil {
		if err := e.newGrpcExporter(queueID); err != nil {
			if e.counter.DropCounter == 0 {
				log.Warningf("new grpc otlp exporter failed. err: %s", err)
			}
			e.counter.DropCounter++
			return err
		}
	}
	_, err := e.grpcExporters[queueID].Export(ctx, req)
	if err != nil {
		if e.counter.DropCounter == 0 {
			log.Warningf("otlp exporter %d send grpc traces failed. faildCounter=%d, err: %s", e.index, e.grpcFailedCounters[queueID], err)
		}
		e.counter.DropCounter++
		e.grpcExporters[queueID] = nil
		return err
	} else {
		e.counter.SendBatchCounter++
	}
	e.counter.ExportUsedTimeNs += int64(time.Since(now))
	return nil
}

func (e *OtlpExporter) getConn(queueID int) (*grpc.ClientConn, error) {
	addrIndex := e.grpcFailedCounters[queueID] % len(e.config.Endpoints)
	var options = []grpc.DialOption{grpc.WithInsecure(), grpc.WithTimeout(time.Minute)}
	conn, err := grpc.Dial(e.config.Endpoints[addrIndex], options...)
	if err != nil {
		// next time, change to next endpoint
		e.grpcFailedCounters[queueID]++
		return nil, fmt.Errorf("grpc dial %s failed, err: %s", e.config.Endpoints[addrIndex], err)
	}
	// next time, change to next endpoint
	e.grpcFailedCounters[queueID]++
	log.Debugf("new grpc otlp exporter: %s", e.config.Endpoints[addrIndex])
	return conn, nil
}

func (e *OtlpExporter) newGrpcExporter(queueID int) error {
	if e.grpcConns[queueID] != nil {
		e.grpcConns[queueID].Close()
		e.grpcConns[queueID] = nil
	}

	conn, err := e.getConn(queueID)
	if err != nil {
		return err
	}

	e.grpcConns[queueID] = conn
	e.grpcExporters[queueID] = ptraceotlp.NewGRPCClient(conn)
	return nil
}

func (e *OtlpExporter) HandleSimpleCommand(op uint16, arg string) string {
	return fmt.Sprintf("otlp exporter %d last 10s counter: %+v", e.index, e.lastCounter)
}

func tracesToString(traces ptrace.Traces) string {
	sb := strings.Builder{}
	for i := 0; i < traces.ResourceSpans().Len(); i++ {
		resourceSpans := traces.ResourceSpans().At(i)
		for j := 0; j < resourceSpans.ScopeSpans().Len(); j++ {
			scopeSpans := resourceSpans.ScopeSpans().At(j)
			for k := 0; k < scopeSpans.Spans().Len(); k++ {
				span := scopeSpans.Spans().At(k)
				sb.WriteString(fmt.Sprintf("Span Name: %s, ", span.Name()))
				sb.WriteString(fmt.Sprintf("Trace ID: %s, ", traceIDToHex(span.TraceID())))
				sb.WriteString(fmt.Sprintf("Span ID: %s, ", spanIDToHex(span.SpanID())))
				sb.WriteString(fmt.Sprintf("Start Timestamp: %d, ", span.StartTimestamp()))
				sb.WriteString(fmt.Sprintf("End Timestamp: %d, ", span.EndTimestamp()))
				sb.WriteString(fmt.Sprintln("Attributes:"))
				span.Attributes().Range(func(k string, v pcommon.Value) bool {
					sb.WriteString(fmt.Sprintf("  %s: %v", k, v))
					return true
				})
			}
		}
	}
	return sb.String()
}

func traceIDToHex(id [16]byte) string {
	var buf [16]byte
	for i := 0; i < 16; i++ {
		buf[i] = id[i]
	}
	return fmt.Sprintf("%x", buf)
}

func spanIDToHex(id [8]byte) string {
	var buf [8]byte
	for i := 0; i < 8; i++ {
		buf[i] = id[i]
	}
	return fmt.Sprintf("%x", buf)
}
