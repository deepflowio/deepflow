package stream

import (
	"net"
	"strconv"
	"time"

	"gitlab.yunshan.net/yunshan/droplet-libs/datatype"
	"gitlab.yunshan.net/yunshan/droplet-libs/debug"
	"gitlab.yunshan.net/yunshan/droplet-libs/grpc"
	"gitlab.yunshan.net/yunshan/droplet-libs/queue"
	libqueue "gitlab.yunshan.net/yunshan/droplet-libs/queue"
	"gitlab.yunshan.net/yunshan/droplet-libs/receiver"
	dropletqueue "gitlab.yunshan.net/yunshan/droplet/droplet/queue"
	"gitlab.yunshan.net/yunshan/droplet/dropletctl"
	"gitlab.yunshan.net/yunshan/droplet/stream/common"
	"gitlab.yunshan.net/yunshan/droplet/stream/config"
	"gitlab.yunshan.net/yunshan/droplet/stream/dbwriter"
	"gitlab.yunshan.net/yunshan/droplet/stream/decoder"
	"gitlab.yunshan.net/yunshan/droplet/stream/geo"
	"gitlab.yunshan.net/yunshan/droplet/stream/throttler"
	_ "golang.org/x/net/context"
	_ "google.golang.org/grpc"
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
	manager := dropletqueue.NewManager(dropletctl.DROPLETCTL_STREAM_QUEUE)
	controllers := make([]net.IP, len(config.ControllerIPs))
	for i, ipString := range config.ControllerIPs {
		controllers[i] = net.ParseIP(ipString)
		if controllers[i].To4() != nil {
			controllers[i] = controllers[i].To4()
		}
	}
	geo.NewGeoTree()

	flowLogWriter, err := dbwriter.NewFlowLogWriter(config.CKDB.Primary, config.CKDB.Secondary, config.CKAuth.User, config.CKAuth.Password, config.ReplicaEnabled, config.CKWriterConfig)
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
		platformDatas[i] = grpc.NewPlatformInfoTable(controllers, config.ControllerPort, "stream-"+datatype.MessageTypeString[msgType]+"-"+strconv.Itoa(i), "", nil)
		if i == 0 {
			debug.ServerRegisterSimple(CMD_PLATFORMDATA, platformDatas[i])
		}
		decoders[i] = decoder.NewDecoder(
			i,
			config.ShardID,
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
		platformDatas[i] = grpc.NewPlatformInfoTable(controllers, config.ControllerPort, "stream-l4-log-"+strconv.Itoa(i), "", nil)
		if i == 0 {
			debug.ServerRegisterSimple(CMD_PLATFORMDATA, platformDatas[i])
		}
		decoders[i] = decoder.NewDecoder(
			i,
			config.ShardID,
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
		platformDatas[i] = grpc.NewPlatformInfoTable(controllers, config.ControllerPort, "stream-l7-log-"+strconv.Itoa(i), "", nil)
		decoders[i] = decoder.NewDecoder(
			i,
			config.ShardID,
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

func (s *Stream) Close() {
	s.FlowLogger.Close()
	s.ProtoLogger.Close()
	s.OtelLogger.Close()
}
