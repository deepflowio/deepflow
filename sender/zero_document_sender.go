package sender

import (
	"strconv"

	"gitlab.x.lan/yunshan/droplet-libs/codec"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
)

type ZeroDocumentSender struct {
	inputQueues []queue.QueueReader
	listenPorts []uint16
}

type zeroDocumentSenderBuilder struct {
	inputQueues []queue.QueueReader
	listenPorts []uint16
}

func NewZeroDocumentSenderBuilder() *zeroDocumentSenderBuilder {
	return &zeroDocumentSenderBuilder{
		inputQueues: make([]queue.QueueReader, 0, 2),
		listenPorts: make([]uint16, 0, 2),
	}
}

func (b *zeroDocumentSenderBuilder) AddQueue(q []queue.QueueReader) *zeroDocumentSenderBuilder {
	b.inputQueues = append(b.inputQueues, q...)
	return b
}

func (b *zeroDocumentSenderBuilder) AddListenPorts(ports ...uint16) *zeroDocumentSenderBuilder {
OUTER:
	for _, newPort := range ports {
		for _, oldPort := range b.listenPorts {
			if newPort == oldPort {
				continue OUTER
			}
		}
		b.listenPorts = append(b.listenPorts, newPort)
	}
	return b
}

func (b *zeroDocumentSenderBuilder) Build() *ZeroDocumentSender {
	return &ZeroDocumentSender{
		inputQueues: b.inputQueues,
		listenPorts: b.listenPorts,
	}
}

func (s *ZeroDocumentSender) Start(queueSize int) {
	lenOfPorts := len(s.listenPorts)
	queueForwards := make([]queue.QueueWriter, lenOfPorts)
	for i := 0; i < lenOfPorts; i++ {
		q := queue.NewOverwriteQueue(
			"6-all-doc-to-zero", queueSize,
			queue.OptionRelease(func(p interface{}) { codec.ReleaseSimpleEncoder(p.(*codec.SimpleEncoder)) }),
			stats.OptionStatTags{"index": strconv.Itoa(i)},
		)
		queueForwards[i] = q
		go NewZMQBytePusher("*", s.listenPorts[i], queueSize).QueueForward(q)
	}
	for _, q := range s.inputQueues {
		go NewZeroDocumentMarshaller(q, queueForwards...).Start()
	}
}
