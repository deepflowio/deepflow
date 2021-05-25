package stream

import (
	"net"
	"strconv"
	"time"

	zmq4 "github.com/pebbe/zmq4"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/receiver"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
	"gitlab.x.lan/yunshan/droplet-libs/zmq"
	dropletqueue "gitlab.x.lan/yunshan/droplet/droplet/queue"
	"gitlab.x.lan/yunshan/droplet/dropletctl"
	"gitlab.x.lan/yunshan/droplet/stream/common"
	"gitlab.x.lan/yunshan/droplet/stream/config"
	"gitlab.x.lan/yunshan/droplet/stream/dbwriter"
	"gitlab.x.lan/yunshan/droplet/stream/decoder"
	"gitlab.x.lan/yunshan/droplet/stream/geo"
	"gitlab.x.lan/yunshan/droplet/stream/platformdata"
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
	Throttlers    []*throttler.ThrottlingQueue
	ESWriters     []*dbwriter.ESWriter
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
	platformdata.New(controllers, config.ControllerPort, "stream", nil)
	geo.NewGeoTree()

	flowLogWriter, err := dbwriter.NewFlowLogWriter(config.CKDB.Primary, config.CKDB.Secondary, config.CKAuth.User, config.CKAuth.Password, config.ReplicaEnabled, config.CKWriterConfig)
	if err != nil {
		return nil, err
	}

	flowLogger, err := NewFlowLogger(config, manager, recv, flowLogWriter)
	protoLogger := NewProtoLogger(config, manager, recv, flowLogWriter)
	return &Stream{
		StreamConfig: config,
		FlowLogger:   flowLogger,
		ProtoLogger:  protoLogger,
	}, nil
}

func newESWriter(config *config.Config, appName string, esQueue queue.QueueReader) *dbwriter.ESWriter {
	return &dbwriter.ESWriter{
		AppName:   appName,
		DataType:  "flow",
		Addresses: config.ESHostPorts,
		User:      config.ESAuth.User,
		Password:  config.ESAuth.Password,
		Replica:   config.ESReplica,
		Tiering:   config.ESTiering,
		RetentionPolicy: common.RetentionPolicy{
			Interval:   common.ZERO,
			SplitSize:  common.Interval(time.Duration(config.RPSplitSize) * time.Second),
			Slots:      config.RPSlots,
			AliveSlots: config.RPAliveSlots,
		},
		OpLoadFactor: config.OpLoadFactor,
		ESQueue:      esQueue,
	}
}

func NewFlowLogger(config *config.Config, manager *dropletqueue.Manager, recv *receiver.Receiver, flowLogWriter *dbwriter.FlowLogWriter) (*Logger, error) {
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
	esWriterQueues := manager.NewQueues(
		"2-decode-to-es-writer-queue"+queueSuffix, (throttler.THROTTLE_BUCKET+1)*throttle, queueCount, 1,
		queue.OptionFlushIndicator((throttler.THROTTLE_BUCKET-1)*time.Second),
	)

	throttlers := make([]*throttler.ThrottlingQueue, queueCount)
	esWriters := make([]*dbwriter.ESWriter, queueCount)
	decoders := make([]*decoder.Decoder, queueCount)

	for i := 0; i < queueCount; i++ {
		throttlers[i] = throttler.NewThrottlingQueue(
			throttle,
			queue.QueueWriter(esWriterQueues.FixedMultiQueue[i]),
			flowLogWriter,
		)
		esWriters[i] = newESWriter(config, common.L4_FLOW_ID.String(), queue.QueueReader(esWriterQueues.FixedMultiQueue[i]))
		decoders[i] = decoder.NewDecoder(
			i,
			config.ShardID,
			msgType,
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
		Throttlers:    throttlers,
		ESWriters:     esWriters,
		FlowLogWriter: flowLogWriter,
		Broker:        broker,
	}, nil

}

func NewProtoLogger(config *config.Config, manager *dropletqueue.Manager, recv *receiver.Receiver, flowLogWriter *dbwriter.FlowLogWriter) *Logger {
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
	httpEsWriterQueues := manager.NewQueues(
		"2-decode-to-es-writer-http"+queueSuffix, (throttler.THROTTLE_BUCKET+1)*httpThrottle, queueCount, 1,
		queue.OptionFlushIndicator((throttler.THROTTLE_BUCKET-1)*time.Second),
	)
	dnsEsWriterQueues := manager.NewQueues(
		"2-decode-to-es-writer-dns"+queueSuffix, (throttler.THROTTLE_BUCKET+1)*dnsThrottle, queueCount, 1,
		queue.OptionFlushIndicator((throttler.THROTTLE_BUCKET-1)*time.Second),
	)

	httpThrottlers := make([]*throttler.ThrottlingQueue, queueCount)
	dnsThrottlers := make([]*throttler.ThrottlingQueue, queueCount)
	httpEsWriters := make([]*dbwriter.ESWriter, queueCount)
	dnsEsWriters := make([]*dbwriter.ESWriter, queueCount)

	decoders := make([]*decoder.Decoder, queueCount)
	for i := 0; i < queueCount; i++ {
		httpThrottlers[i] = throttler.NewThrottlingQueue(
			httpThrottle,
			queue.QueueWriter(httpEsWriterQueues.FixedMultiQueue[i]),
			flowLogWriter,
		)
		dnsThrottlers[i] = throttler.NewThrottlingQueue(
			dnsThrottle,
			queue.QueueWriter(dnsEsWriterQueues.FixedMultiQueue[i]),
			flowLogWriter,
		)
		httpEsWriters[i] = newESWriter(config, common.L7_HTTP_ID.String(), queue.QueueReader(httpEsWriterQueues.FixedMultiQueue[i]))
		dnsEsWriters[i] = newESWriter(config, common.L7_DNS_ID.String(), queue.QueueReader(dnsEsWriterQueues.FixedMultiQueue[i]))
		decoders[i] = decoder.NewDecoder(
			i,
			config.ShardID,
			msgType,
			queue.QueueReader(decodeQueues.FixedMultiQueue[i]),
			nil,
			httpThrottlers[i],
			dnsThrottlers[i],
			false,
			nil,
		)
	}

	return &Logger{
		Config:     config,
		Decoders:   decoders,
		Throttlers: append(httpThrottlers, dnsThrottlers...),
		ESWriters:  append(httpEsWriters, dnsEsWriters...),
	}
}

func (l *Logger) Start() {
	for _, decoder := range l.Decoders {
		go decoder.Run()
	}

	for i, esWriter := range l.ESWriters {
		esWriter.Open(stats.OptionStatTags{"thread": strconv.Itoa(i), "app": esWriter.AppName})
		go esWriter.Run()
	}
}

func (s *Stream) Start() {
	s.FlowLogger.Start()
	s.ProtoLogger.Start()

	if s.StreamConfig.BrokerEnabled {
		go s.FlowLogger.Broker.Run()
	}
	platformdata.Start()
}

func (s *Stream) Close() {
	platformdata.Close()
}
