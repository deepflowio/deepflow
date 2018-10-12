package sender

import (
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
)

type ZeroDocumentSender struct {
	inputQueues []queue.QueueReader
	ips         []string
	ports       []uint16
}

type zeroDocumentSenderBuilder struct {
	inputQueues []queue.QueueReader
	ips         []string
	ports       []uint16
}

func NewZeroDocumentSenderBuilder() *zeroDocumentSenderBuilder {
	return &zeroDocumentSenderBuilder{
		inputQueues: make([]queue.QueueReader, 0, 2),
		ips:         make([]string, 0, 2),
		ports:       make([]uint16, 0, 2),
	}
}

func (b *zeroDocumentSenderBuilder) AddQueue(qs ...queue.QueueReader) *zeroDocumentSenderBuilder {
	for _, q := range qs {
		for _, inputQueue := range b.inputQueues {
			if inputQueue == q {
				return b
			}
		}
		b.inputQueues = append(b.inputQueues, q)
	}
	return b
}

func (b *zeroDocumentSenderBuilder) AddZero(ip string, port uint16) *zeroDocumentSenderBuilder {
	for i := range b.ips {
		if ip == b.ips[i] && b.ports[i] == port {
			return b
		}
	}
	b.ips = append(b.ips, ip)
	b.ports = append(b.ports, port)
	return b
}

func (b *zeroDocumentSenderBuilder) Build() *ZeroDocumentSender {
	return &ZeroDocumentSender{
		inputQueues: b.inputQueues,
		ips:         b.ips,
		ports:       b.ports,
	}
}

func (s *ZeroDocumentSender) Start(queueSize int) {
	queueReaders := make([]queue.QueueReader, len(s.ips))
	queueWriters := make([]queue.QueueWriter, len(s.ips))
	queues := queue.NewOverwriteQueues(
		"6-all-doc-to-zero", uint8(len(s.ips)), queueSize,
		queue.OptionRelease(func(p interface{}) { utils.ReleaseByteBuffer(p.(*utils.ByteBuffer)) }),
	)[:len(s.ips)]
	for i, q := range queues {
		queueReaders[i] = q
		queueWriters[i] = q
	}
	for _, q := range s.inputQueues {
		go NewZeroDocumentMarshaller(q, queueWriters...).Start()
	}
	for i := range s.ips {
		go NewZMQBytePusher(s.ips[i], s.ports[i], queueSize).QueueForward(queueReaders[i])
	}
}
