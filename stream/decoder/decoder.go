package decoder

import (
	logging "github.com/op/go-logging"

	"gitlab.x.lan/yunshan/droplet-libs/codec"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/receiver"
	"gitlab.x.lan/yunshan/droplet/stream/jsonify"
	"gitlab.x.lan/yunshan/droplet/stream/throttler"
)

var log = logging.MustGetLogger("stream.decoder")

const (
	BUFFER_SIZE = 1024
)

type Decoder struct {
	index          int
	msgType        int
	inQueue        queue.QueueReader
	flowThrottler  *throttler.ThrottlingQueue
	httpThrottler  *throttler.ThrottlingQueue
	dnsThrottler   *throttler.ThrottlingQueue
	brokerEnabled  bool
	outBrokerQueue queue.QueueWriter
	debugEnabled   bool
}

func NewDecoder(index, msgType int,
	inQueue queue.QueueReader,
	flowThrottler *throttler.ThrottlingQueue,
	httpThrottler *throttler.ThrottlingQueue,
	dnsThrottler *throttler.ThrottlingQueue,
	brokerEnabled bool,
	outBrokerQueue queue.QueueWriter,
) *Decoder {
	return &Decoder{
		index:          index,
		msgType:        msgType,
		inQueue:        inQueue,
		flowThrottler:  flowThrottler,
		httpThrottler:  httpThrottler,
		dnsThrottler:   dnsThrottler,
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
			if d.msgType == datatype.MESSAGE_TYPE_PROTOCOLLOG {
				d.handleProtoLog(decoder)
			} else if d.msgType == datatype.MESSAGE_TYPE_TAGGEDFLOW {
				d.handleTaggedFlow(decoder)
			}
			receiver.ReleaseRecvBuffer(recvBytes)
		}
	}
}

func (d *Decoder) handleTaggedFlow(decoder *codec.SimpleDecoder) {
	for !decoder.IsEnd() {
		flow := datatype.AcquireTaggedFlow()
		flow.Decode(decoder)
		if decoder.Failed() {
			flow.Release()
			log.Errorf("flow decode failed, offset=%d len=%d", decoder.Offset(), len(decoder.Bytes()))
			return
		}
		d.sendFlow(flow)
	}
}

func (d *Decoder) handleProtoLog(decoder *codec.SimpleDecoder) {
	for !decoder.IsEnd() {
		protoLog := datatype.AcquireAppProtoLogsData()
		protoLog.Decode(decoder)
		if decoder.Failed() {
			protoLog.Release()
			log.Errorf("proto log decode failed, offset=%d len=%d", decoder.Offset(), len(decoder.Bytes()))
			return
		}
		d.sendProto(protoLog)
	}
}

func (d *Decoder) sendFlow(flow *datatype.TaggedFlow) {
	if d.debugEnabled {
		log.Debugf("decoder %d recv flow: %s", d.index, flow)
	}
	if d.brokerEnabled {
		flow.AddReferenceCount()
		d.outBrokerQueue.Put(flow)
	}

	d.flowThrottler.Send(jsonify.TaggedFlowToLogger(flow))
	flow.Release()
}

func (d *Decoder) sendProto(proto *datatype.AppProtoLogsData) {
	if d.debugEnabled {
		log.Debugf("decoder %d recv proto: %s", d.index, proto)
	}
	if proto.Proto == datatype.PROTO_HTTP {
		d.httpThrottler.Send(jsonify.ProtoLogToHTTPLogger(proto))
	} else if proto.Proto == datatype.PROTO_DNS {
		d.dnsThrottler.Send(jsonify.ProtoLogToDNSLogger(proto))
	}
	proto.Release()
}

func (d *Decoder) flush() {
	if d.flowThrottler != nil {
		d.flowThrottler.Send(nil)
	}
	if d.httpThrottler != nil {
		d.httpThrottler.Send(nil)
	}
	if d.dnsThrottler != nil {
		d.dnsThrottler.Send(nil)
	}
}
