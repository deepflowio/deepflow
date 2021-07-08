package stream

import (
	"net"
	"strconv"

	zmq4 "github.com/pebbe/zmq4"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/debug"
	"gitlab.x.lan/yunshan/droplet-libs/grpc"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/receiver"
	"gitlab.x.lan/yunshan/droplet-libs/zmq"
	dropletqueue "gitlab.x.lan/yunshan/droplet/droplet/queue"
	"gitlab.x.lan/yunshan/droplet/dropletctl"
	"gitlab.x.lan/yunshan/droplet/stream/config"
	"gitlab.x.lan/yunshan/droplet/stream/dbwriter"
	"gitlab.x.lan/yunshan/droplet/stream/decoder"
	"gitlab.x.lan/yunshan/droplet/stream/geo"
	"gitlab.x.lan/yunshan/droplet/stream/pusher"
	"gitlab.x.lan/yunshan/droplet/stream/throttler"
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
}

type Logger struct {
	Config        *config.Config
	Decoders      []*decoder.Decoder
	PlatformDatas []*grpc.PlatformInfoTable
	Throttlers    []*throttler.ThrottlingQueue
	Broker        *pusher.FlowSender
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
	flowLogger, err := NewFlowLogger(config, controllers, manager, recv, flowLogWriter)
	protoLogger := NewProtoLogger(config, controllers, manager, recv, flowLogWriter)
	return &Stream{
		StreamConfig: config,
		FlowLogger:   flowLogger,
		ProtoLogger:  protoLogger,
	}, nil
}

func NewFlowLogger(config *config.Config, controllers []net.IP, manager *dropletqueue.Manager, recv *receiver.Receiver, flowLogWriter *dbwriter.FlowLogWriter) (*Logger, error) {
	msgType := datatype.MESSAGE_TYPE_TAGGEDFLOW
	queueCount := config.DecoderQueueCount
	queueSuffix := "-l4"
	decodeQueues := manager.NewQueues(
		"1-receive-to-decode"+queueSuffix,
		config.DecoderQueueSize,
		queueCount,
		1)
	recv.RegistHandler(uint8(msgType), decodeQueues, queueCount)

	var broker *pusher.FlowSender
	var brokerQueue *dropletqueue.Queue
	if config.BrokerEnabled {
		brokerQueue = manager.NewQueue(
			"2-broker-queue"+queueSuffix,
			config.BrokerQueueSize,
		)
		zmqBytePusher := zmq.NewZMQBytePusher(
			config.BrokerZMQIP,
			uint16(config.BrokerZMQPort),
			config.BrokerZMQHWM,
			zmq4.PUB,
		)
		broker = pusher.NewFlowSender(zmqBytePusher, brokerQueue)
	}

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
		)
		platformDatas[i] = grpc.NewPlatformInfoTable(controllers, config.ControllerPort, "stream-l4-log-"+strconv.Itoa(i), "", nil)
		if i == 0 {
			debug.ServerRegisterSimple(CMD_PLATFORMDATA, platformDatas[i])
		}
		decoders[i] = decoder.NewDecoder(
			i,
			msgType,
			config.ShardID,
			platformDatas[i],
			queue.QueueReader(decodeQueues.FixedMultiQueue[i]),
			throttlers[i],
			nil,
			nil,
			config.BrokerEnabled,
			brokerQueue,
		)
	}
	return &Logger{
		Config:        config,
		Decoders:      decoders,
		PlatformDatas: platformDatas,
		Throttlers:    throttlers,
		FlowLogWriter: flowLogWriter,
		Broker:        broker,
	}, nil

}

func NewProtoLogger(config *config.Config, controllers []net.IP, manager *dropletqueue.Manager, recv *receiver.Receiver, flowLogWriter *dbwriter.FlowLogWriter) *Logger {
	queueSuffix := "-l7"
	queueCount := config.DecoderQueueCount
	msgType := datatype.MESSAGE_TYPE_PROTOCOLLOG

	decodeQueues := manager.NewQueues(
		"1-receive-to-decode"+queueSuffix,
		config.DecoderQueueSize,
		queueCount,
		1)

	recv.RegistHandler(uint8(msgType), decodeQueues, queueCount)

	httpThrottle := config.Throttle / queueCount
	if config.L7HTTPThrottle != 0 {
		httpThrottle = config.L7HTTPThrottle / queueCount
	}
	dnsThrottle := config.Throttle / queueCount
	if config.L7DNSThrottle != 0 {
		dnsThrottle = config.L7DNSThrottle / queueCount
	}

	httpThrottlers := make([]*throttler.ThrottlingQueue, queueCount)
	dnsThrottlers := make([]*throttler.ThrottlingQueue, queueCount)

	platformDatas := make([]*grpc.PlatformInfoTable, queueCount)
	decoders := make([]*decoder.Decoder, queueCount)
	for i := 0; i < queueCount; i++ {
		httpThrottlers[i] = throttler.NewThrottlingQueue(
			httpThrottle,
			flowLogWriter,
		)
		dnsThrottlers[i] = throttler.NewThrottlingQueue(
			dnsThrottle,
			flowLogWriter,
		)
		platformDatas[i] = grpc.NewPlatformInfoTable(controllers, config.ControllerPort, "stream-l7-log-"+strconv.Itoa(i), "", nil)
		decoders[i] = decoder.NewDecoder(
			i,
			msgType,
			config.ShardID,
			platformDatas[i],
			queue.QueueReader(decodeQueues.FixedMultiQueue[i]),
			nil,
			httpThrottlers[i],
			dnsThrottlers[i],
			false,
			nil,
		)
	}

	return &Logger{
		Config:        config,
		Decoders:      decoders,
		PlatformDatas: platformDatas,
		Throttlers:    append(httpThrottlers, dnsThrottlers...),
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

	if s.StreamConfig.BrokerEnabled {
		go s.FlowLogger.Broker.Run()
	}
}

func (s *Stream) Close() {
	s.FlowLogger.Close()
	s.ProtoLogger.Close()
}
