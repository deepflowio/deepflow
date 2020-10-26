package decoder

import (
	logging "github.com/op/go-logging"

	"gitlab.x.lan/yunshan/droplet-libs/codec"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/receiver"
	"gitlab.x.lan/yunshan/droplet/stream/throttler"
)

var log = logging.MustGetLogger("stream.decoder")

const (
	BUFFER_SIZE = 1024
)

type Decoder struct {
	index          int
	inQueue        queue.QueueReader
	outThrottler   *throttler.ThrottlingQueue
	brokerEnabled  bool
	outBrokerQueue queue.QueueWriter
	debugEnabled   bool
}

func NewDecoder(index int,
	inQueue queue.QueueReader,
	outThrottler *throttler.ThrottlingQueue,
	brokerEnabled bool,
	outBrokerQueue queue.QueueWriter,
) *Decoder {
	return &Decoder{
		index:          index,
		inQueue:        inQueue,
		outThrottler:   outThrottler,
		brokerEnabled:  brokerEnabled,
		outBrokerQueue: outBrokerQueue,
		debugEnabled:   log.IsEnabledFor(logging.DEBUG),
	}
}

func (d *Decoder) Run() {
	buffer := make([]interface{}, BUFFER_SIZE)
	decoder := &codec.SimpleDecoder{}

	for {
		n := d.inQueue.Gets(buffer)
		for i := 0; i < n; i++ {
			if buffer[i] == nil {
				d.flush()
				continue
			}
			recvBytes, ok := buffer[i].(*receiver.RecvBuffer)
			if !ok {
				log.Warning("get decode queue data type wrong")
				continue
			}
			decoder.Init(recvBytes.Buffer[recvBytes.Begin:recvBytes.End])
			for !decoder.IsEnd() {
				flow := datatype.AcquireTaggedFlow()
				flow.Decode(decoder)
				if decoder.Failed() {
					flow.Release()
					log.Errorf("flow decode failed, offset=%d len=%d", decoder.Offset(), len(decoder.Bytes()))
					continue
				}
				d.handleFlow(flow)
			}
		}
	}
}

func (d *Decoder) handleFlow(flow *datatype.TaggedFlow) {
	if d.debugEnabled {
		log.Debugf("decoder %d recv flow: %s", d.index, flow)
	}
	if d.brokerEnabled {
		flow.AddReferenceCount()
		d.outBrokerQueue.Put(flow)
	}

	d.outThrottler.Send(flow)
}

func (d *Decoder) flush() {
	d.outThrottler.Send(nil)
}
