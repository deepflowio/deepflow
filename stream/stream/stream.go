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
	Decoders     []*decoder.Decoder
	Throttlers   []*throttler.ThrottlingQueue
	ESWriters    []*dbwriter.ESWriter
	Broker       *pusher.FlowSender
}

func NewStream(config *config.Config, recv *receiver.Receiver) *Stream {
	manager := dropletqueue.NewManager(dropletctl.DROPLETCTL_STREAM_QUEUE)

	decodeQueues := manager.NewQueues(
		"1-receive-to-decode",
		config.DecoderQueueSize,
		config.DecoderQueueCount,
		1)

	recv.RegistHandler(datatype.MESSAGE_TYPE_TAGGEDFLOW, decodeQueues, config.DecoderQueueCount)

	queueCount := config.DecoderQueueCount
	throttle := config.Throttle / queueCount
	esWriterQueues := manager.NewQueues(
		"2-decode-to-es-writer-queue", (throttler.THROTTLE_BUCKET+1)*throttle, queueCount, 1,
		queue.OptionFlushIndicator((throttler.THROTTLE_BUCKET-1)*time.Second),
	)

	throttlers := make([]*throttler.ThrottlingQueue, queueCount)
	esWriters := make([]*dbwriter.ESWriter, queueCount)
	for i := 0; i < queueCount; i++ {
		throttlers[i] = throttler.NewThrottlingQueue(
			throttle,
			queue.QueueWriter(esWriterQueues.FixedMultiQueue[i]),
		)

		esWriters[i] = &dbwriter.ESWriter{
			AppName:   "l4_flow_log",
			DataType:  "flow",
			Addresses: config.ESHostPorts,
			User:      config.ESAuth.User,
			Password:  config.ESAuth.Password,
			RetentionPolicy: common.RetentionPolicy{
				Interval:   common.ZERO,
				SplitSize:  common.Interval(time.Duration(config.RPSplitSize) * time.Second),
				Slots:      config.RPSlots,
				AliveSlots: config.RPAliveSlots,
			},
			OpLoadFactor: config.OpLoadFactor,
			ESQueue:      queue.QueueReader(esWriterQueues.FixedMultiQueue[i]),
		}
	}

	var broker *pusher.FlowSender
	var brokerQueue *dropletqueue.Queue
	if config.BrokerEnabled {
		brokerQueue = manager.NewQueue(
			"2-broker_queue",
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

	decoders := make([]*decoder.Decoder, 0)
	for i := 0; i < config.DecoderQueueCount; i++ {
		decoder := decoder.NewDecoder(
			i,
			queue.QueueReader(decodeQueues.FixedMultiQueue[i]),
			throttlers[i],
			config.BrokerEnabled,
			brokerQueue,
		)
		decoders = append(decoders, decoder)
	}

	controllers := make([]net.IP, len(config.ControllerIPs))
	for i, ipString := range config.ControllerIPs {
		controllers[i] = net.ParseIP(ipString)
		if controllers[i].To4() != nil {
			controllers[i] = controllers[i].To4()
		}
	}
	platformdata.New(controllers, config.ControllerPort, "stream", nil)

	geo.NewGeoTree()
	return &Stream{
		StreamConfig: config,
		Decoders:     decoders,
		Throttlers:   throttlers,
		ESWriters:    esWriters,
		Broker:       broker,
	}
}

func (s *Stream) Start() {
	for i := 0; i < s.StreamConfig.DecoderQueueCount; i++ {
		go s.Decoders[i].Run()
		s.ESWriters[i].Open(stats.OptionStatTags{"thread": strconv.Itoa(i)})
		go s.ESWriters[i].Run()

	}
	if s.StreamConfig.BrokerEnabled {
		go s.Broker.Run()
	}
	platformdata.Start()
}

func (s *Stream) Close() {
	platformdata.Close()
}
