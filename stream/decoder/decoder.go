package decoder

import (
	"strconv"

	logging "github.com/op/go-logging"

	"gitlab.x.lan/yunshan/droplet-libs/codec"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/receiver"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
	"gitlab.x.lan/yunshan/droplet/stream/jsonify"
	"gitlab.x.lan/yunshan/droplet/stream/throttler"
)

var log = logging.MustGetLogger("stream.decoder")

const (
	BUFFER_SIZE = 1024
)

type Counter struct {
	RawCount        int64 `statsd:"raw-count"`
	L7HTTPCount     int64 `statsd:"l7-http-count"`
	L7HTTPDropCount int64 `statsd:"l7-http-drop-count"`
	L7DNSCount      int64 `statsd:"l7-dns-count"`
	L7DNSDropCount  int64 `statsd:"l7-dns-drop-count"`
	L4Count         int64 `statsd:"l4-count"`
	L4DropCount     int64 `statsd:"l4-drop-count"`
	ErrorCount      int64 `statsd:"err-count"`
}

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

	counter *Counter
	utils.Closable
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
		counter:        &Counter{},
	}
}

func (d *Decoder) GetCounter() interface{} {
	var counter *Counter
	counter, d.counter = d.counter, &Counter{}
	return counter
}

func (d *Decoder) Run() {
	msgType := "l4"
	if d.msgType == datatype.MESSAGE_TYPE_PROTOCOLLOG {
		msgType = "l7"
	}
	stats.RegisterCountable("decoder", d, stats.OptionStatTags{
		"thread":   strconv.Itoa(d.index),
		"msg_type": msgType})
	buffer := make([]interface{}, BUFFER_SIZE)
	decoder := &codec.SimpleDecoder{}
	for {
		n := d.inQueue.Gets(buffer)
		for i := 0; i < n; i++ {
			if buffer[i] == nil {
				d.flush()
				continue
			}
			d.counter.RawCount++
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
			d.counter.ErrorCount++
			flow.Release()
			log.Errorf("flow decode failed, offset=%d len=%d", decoder.Offset(), len(decoder.Bytes()))
			return
		}
		if flow.StartTime == 0 { // 存在小概率starttime为0的异常数据
			log.Warningf("invalid flow starttime %s", flow)
		}
		d.sendFlow(flow)
	}
}

func (d *Decoder) handleProtoLog(decoder *codec.SimpleDecoder) {
	for !decoder.IsEnd() {
		protoLog := datatype.AcquireAppProtoLogsData()
		protoLog.Decode(decoder)
		if decoder.Failed() {
			d.counter.ErrorCount++
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

	d.counter.L4Count++
	if !d.flowThrottler.Send(jsonify.TaggedFlowToLogger(flow)) {
		d.counter.L4DropCount++
	}
	flow.Release()
}

func (d *Decoder) sendProto(proto *datatype.AppProtoLogsData) {
	if d.debugEnabled {
		log.Debugf("decoder %d recv proto: %s", d.index, proto)
	}
	if proto.Proto == datatype.PROTO_HTTP {
		d.counter.L7HTTPCount++
		if !d.httpThrottler.Send(jsonify.ProtoLogToHTTPLogger(proto)) {
			d.counter.L7HTTPDropCount++
		}
	} else if proto.Proto == datatype.PROTO_DNS {
		d.counter.L7DNSCount++
		if !d.dnsThrottler.Send(jsonify.ProtoLogToDNSLogger(proto)) {
			d.counter.L7DNSDropCount++
		}
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
