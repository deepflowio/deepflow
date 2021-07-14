package pusher

import (
	logging "github.com/op/go-logging"

	"gitlab.yunshan.net/yunshan/droplet-libs/queue"
	"gitlab.yunshan.net/yunshan/droplet-libs/utils"
	"gitlab.yunshan.net/yunshan/droplet-libs/zmq"
	"gitlab.yunshan.net/yunshan/droplet/stream/jsonify"
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
	flows := make([]interface{}, 1024)
	bytes := utils.AcquireByteBuffer()
	for {
		n := flowSend.queue.Gets(flows)
		for _, flow := range flows[:n] {
			if flow == nil {
				continue
			}
			bytes.Reset()
			switch t := flow.(type) {
			case (*jsonify.FlowLogger):
				f := flow.(*jsonify.FlowLogger)
				if err := jsonify.MarshalL4Flow(f, bytes); err != nil {
					f.Release()
					log.Warningf("Marshalling flow failed: %s", err)
					continue
				}
				f.Release()
			case (*jsonify.HTTPLogger):
				f := flow.(*jsonify.HTTPLogger)
				if err := jsonify.MarshalL7HTTP(f, bytes); err != nil {
					f.Release()
					log.Warningf("Marshalling l7HTTP flow failed: %s", err)
					continue
				}
				f.Release()

			case (*jsonify.DNSLogger):
				f := flow.(*jsonify.DNSLogger)
				if err := jsonify.MarshalL7DNS(f, bytes); err != nil {
					f.Release()
					log.Warningf("Marshalling l7DNS flow failed: %s", err)
					continue
				}
				f.Release()
			default:
				log.Warningf("flow type(%T) unsupport", t)
				continue
			}
			flowSend.zmqBytePusher.Send(bytes.Bytes())
		}
	}
}
