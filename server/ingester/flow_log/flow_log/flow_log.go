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

package flow_log

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	logging "github.com/op/go-logging"
	_ "golang.org/x/net/context"
	_ "google.golang.org/grpc"

	dropletqueue "github.com/deepflowio/deepflow/server/ingester/droplet/queue"
	"github.com/deepflowio/deepflow/server/ingester/exporters"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/common"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/config"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/dbwriter"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/decoder"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/geo"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/throttler"
	"github.com/deepflowio/deepflow/server/ingester/flow_tag"
	"github.com/deepflowio/deepflow/server/ingester/ingesterctl"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/debug"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/queue"
	libqueue "github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/receiver"
)

var log = logging.MustGetLogger("flow_log")

type FlowLog struct {
	FlowLogConfig        *config.Config
	L4FlowLogger         *Logger
	L7FlowLogger         *Logger
	OtelLogger           *Logger
	OtelCompressedLogger *Logger
	L4PacketLogger       *Logger
	Exporters            *exporters.Exporters
}

type Logger struct {
	Config        *config.Config
	Decoders      []*decoder.Decoder
	PlatformDatas []*grpc.PlatformInfoTable
	FlowLogWriter *dbwriter.FlowLogWriter
}

func NewFlowLog(config *config.Config, recv *receiver.Receiver, platformDataManager *grpc.PlatformDataManager, exporters *exporters.Exporters) (*FlowLog, error) {
	manager := dropletqueue.NewManager(ingesterctl.INGESTERCTL_FLOW_LOG_QUEUE)

	if config.Base.StorageDisabled {
		l7FlowLogger, err := NewL7FlowLogger(config, platformDataManager, manager, recv, nil, exporters)
		if err != nil {
			return nil, err
		}
		return &FlowLog{
			L7FlowLogger: l7FlowLogger,
			Exporters:    exporters,
		}, nil
	}

	geo.NewGeoTree()

	flowLogWriter, err := dbwriter.NewFlowLogWriter(
		config.Base.CKDB.ActualAddrs, config.Base.CKDBAuth.Username, config.Base.CKDBAuth.Password,
		config.Base.CKDB.ClusterName, config.Base.CKDB.StoragePolicy, config.Base.CKDB.TimeZone,
		config.CKWriterConfig, config.FlowLogTTL, config.Base.GetCKDBColdStorages(), config.Base.CKDB.Watcher)
	if err != nil {
		return nil, err
	}
	l4FlowLogger := NewL4FlowLogger(config, platformDataManager, manager, recv, flowLogWriter, exporters)

	l7FlowLogger, err := NewL7FlowLogger(config, platformDataManager, manager, recv, flowLogWriter, exporters)
	if err != nil {
		return nil, err
	}
	otelLogger, err := NewLogger(datatype.MESSAGE_TYPE_OPENTELEMETRY, config, platformDataManager, manager, recv, flowLogWriter, common.L7_FLOW_ID, nil)
	if err != nil {
		return nil, err
	}
	otelCompressedLogger, err := NewLogger(datatype.MESSAGE_TYPE_OPENTELEMETRY_COMPRESSED, config, platformDataManager, manager, recv, flowLogWriter, common.L7_FLOW_ID, nil)
	if err != nil {
		return nil, err
	}
	l4PacketLogger, err := NewLogger(datatype.MESSAGE_TYPE_PACKETSEQUENCE, config, nil, manager, recv, flowLogWriter, common.L4_PACKET_ID, nil)
	if err != nil {
		return nil, err
	}
	return &FlowLog{
		FlowLogConfig:        config,
		L4FlowLogger:         l4FlowLogger,
		L7FlowLogger:         l7FlowLogger,
		OtelLogger:           otelLogger,
		OtelCompressedLogger: otelCompressedLogger,
		L4PacketLogger:       l4PacketLogger,
		Exporters:            exporters,
	}, nil
}

func NewLogger(msgType datatype.MessageType, config *config.Config, platformDataManager *grpc.PlatformDataManager, manager *dropletqueue.Manager, recv *receiver.Receiver, flowLogWriter *dbwriter.FlowLogWriter, flowLogId common.FlowLogID, exporters *exporters.Exporters) (*Logger, error) {
	queueCount := config.DecoderQueueCount
	decodeQueues := manager.NewQueues(
		"1-receive-to-decode-"+datatype.MessageTypeString[msgType],
		config.DecoderQueueSize,
		queueCount,
		1,
		libqueue.OptionFlushIndicator(3*time.Second),
		libqueue.OptionRelease(func(p interface{}) { receiver.ReleaseRecvBuffer(p.(*receiver.RecvBuffer)) }))
	recv.RegistHandler(msgType, decodeQueues, queueCount)
	throttle := config.Throttle / queueCount

	throttlers := make([]*throttler.ThrottlingQueue, queueCount)
	decoders := make([]*decoder.Decoder, queueCount)
	platformDatas := make([]*grpc.PlatformInfoTable, queueCount)
	for i := 0; i < queueCount; i++ {
		flowTagWriter, err := flow_tag.NewFlowTagWriter(i, msgType.String(), common.FLOW_LOG_DB, config.FlowLogTTL.L7FlowLog, ckdb.TimeFuncTwelveHour, config.Base, &config.CKWriterConfig)
		if err != nil {
			return nil, err
		}
		throttlers[i] = throttler.NewThrottlingQueue(
			throttle,
			config.ThrottleBucket,
			flowLogWriter,
			int(flowLogId),
		)
		if platformDataManager != nil {
			platformDatas[i], _ = platformDataManager.NewPlatformInfoTable("flow-log-" + datatype.MessageTypeString[msgType] + "-" + strconv.Itoa(i))
			if i == 0 {
				debug.ServerRegisterSimple(ingesterctl.CMD_PLATFORMDATA_FLOW_LOG, platformDatas[i])
			}
		}
		decoders[i] = decoder.NewDecoder(
			i,
			msgType,
			platformDatas[i],
			queue.QueueReader(decodeQueues.FixedMultiQueue[i]),
			throttlers[i],
			flowTagWriter,
			exporters,
			config,
		)
	}
	return &Logger{
		Config:        config,
		Decoders:      decoders,
		PlatformDatas: platformDatas,
		FlowLogWriter: flowLogWriter,
	}, nil
}

func NewL4FlowLogger(config *config.Config, platformDataManager *grpc.PlatformDataManager, manager *dropletqueue.Manager, recv *receiver.Receiver, flowLogWriter *dbwriter.FlowLogWriter, exporters *exporters.Exporters) *Logger {
	msgType := datatype.MESSAGE_TYPE_TAGGEDFLOW
	queueCount := config.DecoderQueueCount
	queueSuffix := "-l4"
	decodeQueues := manager.NewQueues(
		"1-receive-to-decode"+queueSuffix,
		config.DecoderQueueSize,
		queueCount,
		1,
		libqueue.OptionFlushIndicator(3*time.Second),
		libqueue.OptionRelease(func(p interface{}) { receiver.ReleaseRecvBuffer(p.(*receiver.RecvBuffer)) }))

	recv.RegistHandler(msgType, decodeQueues, queueCount)

	throttle := config.Throttle / queueCount
	if config.L4Throttle != 0 {
		throttle = config.L4Throttle / queueCount
	}

	throttlers := make([]*throttler.ThrottlingQueue, queueCount)
	decoders := make([]*decoder.Decoder, queueCount)
	platformDatas := make([]*grpc.PlatformInfoTable, queueCount)

	for i := 0; i < queueCount; i++ {
		throttlers[i] = throttler.NewThrottlingQueue(
			throttle,
			config.ThrottleBucket,
			flowLogWriter,
			int(common.L4_FLOW_ID),
		)
		platformDatas[i], _ = platformDataManager.NewPlatformInfoTable("l4-flow-log-" + strconv.Itoa(i))
		if i == 0 {
			debug.ServerRegisterSimple(ingesterctl.CMD_PLATFORMDATA_FLOW_LOG, platformDatas[i])
		}
		decoders[i] = decoder.NewDecoder(
			i,
			msgType,
			platformDatas[i],
			queue.QueueReader(decodeQueues.FixedMultiQueue[i]),
			throttlers[i],
			nil,
			exporters,
			config,
		)
	}
	return &Logger{
		Config:        config,
		Decoders:      decoders,
		PlatformDatas: platformDatas,
		FlowLogWriter: flowLogWriter,
	}
}

func NewL7FlowLogger(config *config.Config, platformDataManager *grpc.PlatformDataManager, manager *dropletqueue.Manager, recv *receiver.Receiver, flowLogWriter *dbwriter.FlowLogWriter, exporters *exporters.Exporters) (*Logger, error) {
	queueSuffix := "-l7"
	queueCount := config.DecoderQueueCount
	msgType := datatype.MESSAGE_TYPE_PROTOCOLLOG

	decodeQueues := manager.NewQueues(
		"1-receive-to-decode"+queueSuffix,
		config.DecoderQueueSize,
		queueCount,
		1,
		libqueue.OptionFlushIndicator(3*time.Second),
		libqueue.OptionRelease(func(p interface{}) { receiver.ReleaseRecvBuffer(p.(*receiver.RecvBuffer)) }))

	recv.RegistHandler(msgType, decodeQueues, queueCount)

	throttle := config.Throttle / queueCount
	if config.L7Throttle != 0 {
		throttle = config.L7Throttle / queueCount
	}

	throttlers := make([]*throttler.ThrottlingQueue, queueCount)

	platformDatas := make([]*grpc.PlatformInfoTable, queueCount)
	decoders := make([]*decoder.Decoder, queueCount)
	var flowTagWriter *flow_tag.FlowTagWriter
	var err error
	for i := 0; i < queueCount; i++ {
		if flowLogWriter != nil {
			flowTagWriter, err = flow_tag.NewFlowTagWriter(i, msgType.String(), common.FLOW_LOG_DB, config.FlowLogTTL.L7FlowLog, ckdb.TimeFuncTwelveHour, config.Base, &config.CKWriterConfig)
			if err != nil {
				return nil, err
			}
		}
		throttlers[i] = throttler.NewThrottlingQueue(
			throttle,
			config.ThrottleBucket,
			flowLogWriter,
			int(common.L7_FLOW_ID),
		)
		platformDatas[i], _ = platformDataManager.NewPlatformInfoTable("l7-flow-log-" + strconv.Itoa(i))
		if i == 0 {
			debug.ServerRegisterSimple(ingesterctl.CMD_PLATFORMDATA_FLOW_LOG, platformDatas[i])
		}
		decoders[i] = decoder.NewDecoder(
			i,
			msgType,
			platformDatas[i],
			queue.QueueReader(decodeQueues.FixedMultiQueue[i]),
			throttlers[i],
			flowTagWriter,
			exporters,
			config,
		)
	}

	l := &Logger{
		Config:        config,
		Decoders:      decoders,
		PlatformDatas: platformDatas,
	}
	debug.ServerRegisterSimple(ingesterctl.CMD_L7_FLOW_LOG, l)
	return l, nil
}

func (l *Logger) HandleSimpleCommand(op uint16, arg string) string {
	sb := &strings.Builder{}
	sb.WriteString("last 10s counter:\n")
	for i, d := range l.Decoders {
		sb.WriteString(fmt.Sprintf("  decoder %d: %+v\n", i, d.GetLastCounter()))
	}
	return sb.String()
}

func (l *Logger) Start() {
	for _, platformData := range l.PlatformDatas {
		if platformData != nil {
			platformData.Start()
		}
	}

	for _, decoder := range l.Decoders {
		go decoder.Run()
	}
}

func (l *Logger) Close() {
	for _, platformData := range l.PlatformDatas {
		if platformData != nil {
			platformData.ClosePlatformInfoTable()
		}
	}
}

func (s *FlowLog) Start() {
	if s.L4FlowLogger != nil {
		s.L4FlowLogger.Start()
	}
	if s.L7FlowLogger != nil {
		s.L7FlowLogger.Start()
	}
	if s.L4PacketLogger != nil {
		s.L4PacketLogger.Start()
	}
	if s.OtelLogger != nil {
		s.OtelLogger.Start()
	}
	if s.OtelCompressedLogger != nil {
		s.OtelCompressedLogger.Start()
	}
	if s.Exporters != nil {
		s.Exporters.Start()
	}
}

func (s *FlowLog) Close() error {
	if s.L4FlowLogger != nil {
		s.L4FlowLogger.Close()
	}
	if s.L7FlowLogger != nil {
		s.L7FlowLogger.Close()
	}
	if s.L4PacketLogger != nil {
		s.L4PacketLogger.Close()
	}
	if s.OtelLogger != nil {
		s.OtelLogger.Close()
	}
	if s.OtelCompressedLogger != nil {
		s.OtelCompressedLogger.Close()
	}
	if s.Exporters != nil {
		s.Exporters.Close()
	}
	return nil
}
