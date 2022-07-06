package stream

import (
	"net"
	"strconv"
	"time"

	_ "golang.org/x/net/context"
	_ "google.golang.org/grpc"

	dropletqueue "github.com/metaflowys/metaflow/server/ingester/droplet/queue"
	"github.com/metaflowys/metaflow/server/ingester/ingesterctl"
	"github.com/metaflowys/metaflow/server/ingester/stream/common"
	"github.com/metaflowys/metaflow/server/ingester/stream/config"
	"github.com/metaflowys/metaflow/server/ingester/stream/dbwriter"
	"github.com/metaflowys/metaflow/server/ingester/stream/decoder"
	"github.com/metaflowys/metaflow/server/ingester/stream/geo"
	"github.com/metaflowys/metaflow/server/ingester/stream/throttler"
	"github.com/metaflowys/metaflow/server/libs/datatype"
	"github.com/metaflowys/metaflow/server/libs/debug"
	"github.com/metaflowys/metaflow/server/libs/grpc"
	"github.com/metaflowys/metaflow/server/libs/queue"
	libqueue "github.com/metaflowys/metaflow/server/libs/queue"
	"github.com/metaflowys/metaflow/server/libs/receiver"
)

const (
	CMD_PLATFORMDATA = 34
)

type Stream struct {
	StreamConfig *config.Config
	FlowLogger   *Logger
	ProtoLogger  *Logger
	OtelLogger   *Logger
}

type Logger struct {
	Config        *config.Config
	Decoders      []*decoder.Decoder
	PlatformDatas []*grpc.PlatformInfoTable
	FlowLogWriter *dbwriter.FlowLogWriter
}

func NewStream(config *config.Config, recv *receiver.Receiver) (*Stream, error) {
	manager := dropletqueue.NewManager(ingesterctl.INGESTERCTL_STREAM_QUEUE)
	controllers := make([]net.IP, len(config.Base.ControllerIPs))
	for i, ipString := range config.Base.ControllerIPs {
		controllers[i] = net.ParseIP(ipString)
		if controllers[i].To4() != nil {
			controllers[i] = controllers[i].To4()
		}
	}
	geo.NewGeoTree()

	flowLogWriter, err := dbwriter.NewFlowLogWriter(config.Base.CKDB.Primary, config.Base.CKDB.Secondary, config.Base.CKDBAuth.Username, config.Base.CKDBAuth.Password, config.ReplicaEnabled, config.CKWriterConfig)
	if err != nil {
		return nil, err
	}
	flowLogger := NewFlowLogger(config, controllers, manager, recv, flowLogWriter)
	protoLogger := NewProtoLogger(config, controllers, manager, recv, flowLogWriter)
	otelLogger := NewLogger(datatype.MESSAGE_TYPE_OPENTELEMETRY, config, controllers, manager, recv, flowLogWriter, common.L7_FLOW_ID)
	return &Stream{
		StreamConfig: config,
		FlowLogger:   flowLogger,
		ProtoLogger:  protoLogger,
		OtelLogger:   otelLogger,
	}, nil
}

func NewLogger(msgType datatype.MessageType, config *config.Config, controllers []net.IP, manager *dropletqueue.Manager, recv *receiver.Receiver, flowLogWriter *dbwriter.FlowLogWriter, flowLogId common.FlowLogID) *Logger {
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
		throttlers[i] = throttler.NewThrottlingQueue(
			throttle,
			flowLogWriter,
			int(flowLogId),
		)
		platformDatas[i] = grpc.NewPlatformInfoTable(controllers, int(config.Base.ControllerPort), "stream-"+datatype.MessageTypeString[msgType]+"-"+strconv.Itoa(i), "", config.Base.NodeIP, nil)
		if i == 0 {
			debug.ServerRegisterSimple(CMD_PLATFORMDATA, platformDatas[i])
		}
		decoders[i] = decoder.NewDecoder(
			i,
			config.Base.ShardID,
			msgType,
			platformDatas[i],
			queue.QueueReader(decodeQueues.FixedMultiQueue[i]),
			throttlers[i],
			&config.FlowLogDisabled,
		)
	}
	return &Logger{
		Config:        config,
		Decoders:      decoders,
		PlatformDatas: platformDatas,
		FlowLogWriter: flowLogWriter,
	}
}

func NewFlowLogger(config *config.Config, controllers []net.IP, manager *dropletqueue.Manager, recv *receiver.Receiver, flowLogWriter *dbwriter.FlowLogWriter) *Logger {
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
			flowLogWriter,
			int(common.L4_FLOW_ID),
		)
		platformDatas[i] = grpc.NewPlatformInfoTable(controllers, int(config.Base.ControllerPort), "stream-l4-log-"+strconv.Itoa(i), "", config.Base.NodeIP, nil)
		if i == 0 {
			debug.ServerRegisterSimple(CMD_PLATFORMDATA, platformDatas[i])
		}
		decoders[i] = decoder.NewDecoder(
			i,
			config.Base.ShardID,
			msgType,
			platformDatas[i],
			queue.QueueReader(decodeQueues.FixedMultiQueue[i]),
			throttlers[i],
			&config.FlowLogDisabled,
		)
	}
	return &Logger{
		Config:        config,
		Decoders:      decoders,
		PlatformDatas: platformDatas,
		FlowLogWriter: flowLogWriter,
	}
}

func NewProtoLogger(config *config.Config, controllers []net.IP, manager *dropletqueue.Manager, recv *receiver.Receiver, flowLogWriter *dbwriter.FlowLogWriter) *Logger {
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
	for i := 0; i < queueCount; i++ {
		throttlers[i] = throttler.NewThrottlingQueue(
			throttle,
			flowLogWriter,
			int(common.L7_FLOW_ID),
		)
		platformDatas[i] = grpc.NewPlatformInfoTable(controllers, int(config.Base.ControllerPort), "stream-l7-log-"+strconv.Itoa(i), "", config.Base.NodeIP, nil)
		decoders[i] = decoder.NewDecoder(
			i,
			config.Base.ShardID,
			msgType,
			platformDatas[i],
			queue.QueueReader(decodeQueues.FixedMultiQueue[i]),
			throttlers[i],
			&config.FlowLogDisabled,
		)
	}

	return &Logger{
		Config:        config,
		Decoders:      decoders,
		PlatformDatas: platformDatas,
	}
}

func (l *Logger) Start() {
	for _, platformData := range l.PlatformDatas {
		platformData.Start()
	}

	for _, decoder := range l.Decoders {
		go decoder.Run()
	}
}

func (l *Logger) Close() {
	for _, platformData := range l.PlatformDatas {
		platformData.Close()
	}
}

func (s *Stream) Start() {
	s.FlowLogger.Start()
	s.ProtoLogger.Start()
	s.OtelLogger.Start()
}

func (s *Stream) Close() error {
	s.FlowLogger.Close()
	s.ProtoLogger.Close()
	s.OtelLogger.Close()
	return nil
}
