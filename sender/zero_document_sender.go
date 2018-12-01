package sender

import (
	"strconv"

	"gitlab.x.lan/yunshan/droplet-libs/codec"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
)

type ZeroDocumentSender struct {
	inputQueues []queue.MultiQueueReader
	queueCounts []int
	listenPorts []uint16
}

type zeroDocumentSenderBuilder struct {
	inputQueues []queue.MultiQueueReader
	queueCounts []int
	listenPorts []uint16
}

func NewZeroDocumentSenderBuilder() *zeroDocumentSenderBuilder {
	return &zeroDocumentSenderBuilder{
		inputQueues: make([]queue.MultiQueueReader, 0, 2),
		queueCounts: make([]int, 0, 2),
		listenPorts: make([]uint16, 0, 2),
	}
}

func (b *zeroDocumentSenderBuilder) AddQueue(q queue.MultiQueueReader, count int) *zeroDocumentSenderBuilder {
	for _, inputQueue := range b.inputQueues {
		if &inputQueue == &q {
			return b
		}
	}
	b.inputQueues = append(b.inputQueues, q)
	b.queueCounts = append(b.queueCounts, count)
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
		queueCounts: b.queueCounts,
		listenPorts: b.listenPorts,
	}
}

func (s *ZeroDocumentSender) Start(queueSize int) {
	lenOfPorts := len(s.listenPorts)
	queueWriters := make([]queue.QueueWriter, lenOfPorts)
	for i := 0; i < lenOfPorts; i++ {
		q := queue.NewOverwriteQueue(
			"6-all-doc-to-zero", queueSize,
			queue.OptionRelease(func(p interface{}) { codec.ReleaseSimpleEncoder(p.(*codec.SimpleEncoder)) }),
			stats.OptionStatTags{"index": strconv.Itoa(i)},
		)
		queueWriters[i] = q
		go NewZMQBytePusher("*", s.listenPorts[i], queueSize).QueueForward(q)
	}
	for i, q := range s.inputQueues {
		for key := 0; key < s.queueCounts[i]; key++ {
			go NewZeroDocumentMarshaller(q, queue.HashKey(key), queueWriters...).Start()
		}
	}
}
