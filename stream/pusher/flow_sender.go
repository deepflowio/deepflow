package pusher

import (
	logging "github.com/op/go-logging"

	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/protobuf"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
	"gitlab.x.lan/yunshan/droplet-libs/zmq"
)

var log = logging.MustGetLogger("stream.pusher")

type FlowSender struct {
	zmqBytePusher *zmq.ZMQBytePusher
	queue         queue.QueueReader
}

func NewFlowSender(zmqBytePusher *zmq.ZMQBytePusher, queue queue.QueueReader) *FlowSender {
	return &FlowSender{
		zmqBytePusher,
		queue,
	}
}

func (flowSend *FlowSender) Run() {
	bytes := utils.AcquireByteBuffer()
	for {
		flow, ok := flowSend.queue.Get().(*datatype.TaggedFlow)
		if !ok {
			log.Warningf("Get queue message type failed, should be *TaggedFlow")
			continue
		}
		bytes.Reset()
		if err := protobuf.MarshalFlow(flow, bytes); err != nil {
			datatype.ReleaseTaggedFlow(flow)
			log.Warningf("Marshalling flow failed: %s", err)
			continue
		}
		datatype.ReleaseTaggedFlow(flow)
		flowSend.zmqBytePusher.Send(bytes.Bytes())
	}
}
