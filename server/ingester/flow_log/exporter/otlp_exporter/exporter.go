/*
 * Copyright (c) 2023 Yunshan Networks
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
	"time"

	logging "github.com/op/go-logging"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/log_data"
	"github.com/deepflowio/deepflow/server/ingester/ingesterctl"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/debug"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

var log = logging.MustGetLogger("flow_log.exporter")

const (
	QUEUE_BATCH_COUNT = 1024
)

type OtlpExporter struct {
	Addr                 string
	dataQueues           queue.FixedMultiQueue
	queueCount           int
	grpcExporters        []ptraceotlp.GRPCClient
	grpcConns            []*grpc.ClientConn
	universalTagsManager *UniversalTagsManager
	config               *OtlpExporterConfig
	counter              *Counter
	lastCounter          Counter
	exportDataBits       uint32
	exportDataTypeBits   uint32

	utils.Closable
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
	K8S_LABEL
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
	"k8s_label":            K8S_LABEL,
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

type ExportItem interface {
	Release()
}

func NewOtlpExporter(config *OtlpExporterConfig, baseConfig *config.Config) *OtlpExporter {
	exportConfig := config
	if !exportConfig.Enabled {
		log.Info("otlp exporter disabled")
		return nil
	}
	exportDataBits := uint32(0)
	for _, v := range config.ExportDatas {
		exportDataBits |= uint32(StringToExportedData(v))
	}
	log.Infof("export data bits: %08b, string: %s", exportDataBits, ExportedDataBitsToString(exportDataBits))

	exportDataTypeBits := uint32(0)
	for _, v := range config.ExportDataTypes {
		exportDataTypeBits |= uint32(StringToExportedDataType(v))
	}
	if config.ExportCustomK8sLabelsRegexp != "" {
		exportDataTypeBits |= K8S_LABEL
	}
	log.Infof("export data type bits: %08b, string: %s", exportDataTypeBits, ExportedDataTypeBitsToString(exportDataTypeBits))

	dataQueues := queue.NewOverwriteQueues(
		"exporter", queue.HashKey(exportConfig.QueueCount), exportConfig.QueueSize,
		queue.OptionFlushIndicator(time.Second),
		queue.OptionRelease(func(p interface{}) { p.(ExportItem).Release() }),
		common.QUEUE_STATS_MODULE_INGESTER)

	universalTagsManager := NewUniversalTagsManager(config, baseConfig)
	exporter := &OtlpExporter{
		dataQueues:           dataQueues,
		queueCount:           exportConfig.QueueCount,
		universalTagsManager: universalTagsManager,
		grpcConns:            make([]*grpc.ClientConn, exportConfig.QueueCount),
		grpcExporters:        make([]ptraceotlp.GRPCClient, exportConfig.QueueCount),
		config:               config,
		exportDataBits:       exportDataBits,
		exportDataTypeBits:   exportDataTypeBits,
		counter:              &Counter{},
	}
	debug.ServerRegisterSimple(ingesterctl.CMD_OTLP_EXPORTER, exporter)
	common.RegisterCountableForIngester("exporter", exporter)
	log.Info("otlp exporter start")
	return exporter
}

func (e *OtlpExporter) IsExportData(item interface{}) bool {
	signalSource, ok := item.(datatype.SignalSource)
	if !ok {
		return false
	}

	// always not export data from OTel
	if signalSource == datatype.SIGNAL_SOURCE_OTEL {
		return false
	}
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
	var batchCount int
	traces := ptrace.NewTraces()
	flows := make([]interface{}, QUEUE_BATCH_COUNT)

	ctx := context.Background()
	if len(e.config.GrpcHeaders) > 0 {
		ctx = metadata.NewOutgoingContext(ctx, metadata.New(e.config.GrpcHeaders))
	}
	for {
		n := e.dataQueues.Gets(queue.HashKey(queueID), flows)
		for _, flow := range flows[:n] {
			if flow == nil {
				if batchCount > 0 {
					if err := e.grpcExport(ctx, queueID, ptraceotlp.NewExportRequestFromTraces(traces)); err == nil {
						e.counter.SendCounter += int64(batchCount)
					}
					batchCount = 0
					traces = ptrace.NewTraces()
				}
				continue
			}
			switch t := flow.(type) {
			case (*log_data.L7FlowLog):
				f := flow.(*log_data.L7FlowLog)
				if e.config.ExportOnlyWithTraceID && f.TraceId == "" {
					e.counter.DropNoTraceIDCounter++
					e.counter.DropCounter++
					f.Release()
					continue
				}

				L7FlowLogToExportResourceSpans(f, e.universalTagsManager, e.exportDataTypeBits, traces.ResourceSpans().AppendEmpty())
				batchCount++
				if batchCount >= e.config.ExportBatchCount {
					if err := e.grpcExport(ctx, queueID, ptraceotlp.NewExportRequestFromTraces(traces)); err == nil {
						e.counter.SendCounter += int64(batchCount)
					}
					batchCount = 0
					traces = ptrace.NewTraces()
				}

				f.Release()
			default:
				log.Warningf("flow type(%T) unsupport", t)
				continue
			}
		}
	}
}

func (e *OtlpExporter) grpcExport(ctx context.Context, i int, req ptraceotlp.ExportRequest) error {
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
			log.Warningf("send grpc traces failed. err: %s", err)
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
	conn, err := grpc.Dial(e.config.Addr, options...)
	if err != nil {
		return fmt.Errorf("grpc dial %s failed, err: %s", e.config.Addr, err)
	}
	log.Debugf("new grpc otlp exporter: %s", e.config.Addr)
	e.grpcConns[i] = conn
	e.grpcExporters[i] = ptraceotlp.NewGRPCClient(conn)
	return nil
}

func (e *OtlpExporter) HandleSimpleCommand(op uint16, arg string) string {
	return fmt.Sprintf("last 10s counter: %+v", e.lastCounter)
}
