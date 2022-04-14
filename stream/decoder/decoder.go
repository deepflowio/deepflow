package decoder

import (
	"strconv"

	logging "github.com/op/go-logging"
	"gitlab.yunshan.net/yunshan/droplet-libs/zerodoc"

	"gitlab.yunshan.net/yunshan/droplet-libs/codec"
	"gitlab.yunshan.net/yunshan/droplet-libs/datatype"
	"gitlab.yunshan.net/yunshan/droplet-libs/datatype/pb"
	"gitlab.yunshan.net/yunshan/droplet-libs/grpc"
	"gitlab.yunshan.net/yunshan/droplet-libs/queue"
	"gitlab.yunshan.net/yunshan/droplet-libs/receiver"
	"gitlab.yunshan.net/yunshan/droplet-libs/stats"
	"gitlab.yunshan.net/yunshan/droplet-libs/utils"
	"gitlab.yunshan.net/yunshan/droplet/stream/config"
	"gitlab.yunshan.net/yunshan/droplet/stream/jsonify"
	"gitlab.yunshan.net/yunshan/droplet/stream/throttler"
)

var log = logging.MustGetLogger("stream.decoder")

const (
	BUFFER_SIZE  = 1024
	L7_PROTO_MAX = datatype.PROTO_DNS + 1
)

type Counter struct {
	RawCount         int64 `statsd:"raw-count"`
	L4Count          int64 `statsd:"l4-count"`
	L4DropCount      int64 `statsd:"l4-drop-count"`
	L7Count          int64 `statsd:"l7-count"`
	L7DropCount      int64 `statsd:"l7-drop-count"`
	L7HTTPCount      int64 `statsd:"l7-http-count"`
	L7HTTPDropCount  int64 `statsd:"l7-http-drop-count"`
	L7DNSCount       int64 `statsd:"l7-dns-count"`
	L7DNSDropCount   int64 `statsd:"l7-dns-drop-count"`
	L7SQLCount       int64 `statsd:"l7-sql-count"`
	L7SQLDropCount   int64 `statsd:"l7-sql-drop-count"`
	L7NoSQLCount     int64 `statsd:"l7-nosql-count"`
	L7NoSQLDropCount int64 `statsd:"l7-nosql-drop-count"`
	L7RPCCount       int64 `statsd:"l7-rpc-count"`
	L7RPCDropCount   int64 `statsd:"l7-rpc-drop-count"`
	L7MQCount        int64 `statsd:"l7-mq-count"`
	L7MQDropCount    int64 `statsd:"l7-mq-drop-count"`
	ErrorCount       int64 `statsd:"err-count"`
}

type Decoder struct {
	index        int
	msgType      int
	shardID      int
	platformData *grpc.PlatformInfoTable
	inQueue      queue.QueueReader
	throttler    *throttler.ThrottlingQueue
	debugEnabled bool

	l7Disableds [L7_PROTO_MAX]bool
	l7Disabled  bool
	l4Disabled  bool

	counter *Counter
	utils.Closable
}

func NewDecoder(
	index, msgType, shardID int,
	platformData *grpc.PlatformInfoTable,
	inQueue queue.QueueReader,
	throttler *throttler.ThrottlingQueue,
	flowLogDisabled *config.FlowLogDisabled,
) *Decoder {
	return &Decoder{
		index:        index,
		msgType:      msgType,
		shardID:      shardID,
		platformData: platformData,
		inQueue:      inQueue,
		throttler:    throttler,
		debugEnabled: log.IsEnabledFor(logging.DEBUG),
		counter:      &Counter{},
		l7Disableds:  getL7Disables(flowLogDisabled),
		l7Disabled:   flowLogDisabled.L7,
		l4Disabled:   flowLogDisabled.L4,
	}
}

func getL7Disables(flowLogConfig *config.FlowLogDisabled) [L7_PROTO_MAX]bool {
	l7Disableds := [L7_PROTO_MAX]bool{}
	l7Disableds[datatype.PROTO_HTTP_1] = flowLogConfig.Http
	l7Disableds[datatype.PROTO_HTTP_2] = flowLogConfig.Http
	l7Disableds[datatype.PROTO_DNS] = flowLogConfig.Dns
	l7Disableds[datatype.PROTO_MYSQL] = flowLogConfig.Mysql
	l7Disableds[datatype.PROTO_REDIS] = flowLogConfig.Redis
	l7Disableds[datatype.PROTO_DUBBO] = flowLogConfig.Dubbo
	l7Disableds[datatype.PROTO_KAFKA] = flowLogConfig.Kafka
	return l7Disableds
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
	pbTaggedFlow := pb.NewTaggedFlow()
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
			if d.msgType == datatype.MESSAGE_TYPE_PROTOCOLLOG && !d.l7Disabled {
				d.handleProtoLog(decoder)
			} else if d.msgType == datatype.MESSAGE_TYPE_TAGGEDFLOW && !d.l4Disabled {
				d.handleTaggedFlow(decoder, pbTaggedFlow)
			}
			receiver.ReleaseRecvBuffer(recvBytes)
		}
	}
}

func (d *Decoder) handleTaggedFlow(decoder *codec.SimpleDecoder, pbTaggedFlow *pb.TaggedFlow) {
	for !decoder.IsEnd() {
		pbTaggedFlow.ResetAll()
		decoder.ReadPB(pbTaggedFlow)
		if decoder.Failed() {
			d.counter.ErrorCount++
			log.Errorf("flow decode failed, offset=%d len=%d", decoder.Offset(), len(decoder.Bytes()))
			return
		}
		if !pbTaggedFlow.IsValid() {
			d.counter.ErrorCount++
			log.Warningf("invalid flow %s", pbTaggedFlow.Flow)
			continue
		}
		d.sendFlow(pbTaggedFlow)
	}
}

func (d *Decoder) handleProtoLog(decoder *codec.SimpleDecoder) {
	for !decoder.IsEnd() {
		protoLog := pb.AcquirePbAppProtoLogsData()

		decoder.ReadPB(protoLog)
		if decoder.Failed() || !protoLog.IsValid() {
			d.counter.ErrorCount++
			pb.ReleasePbAppProtoLogsData(protoLog)
			log.Errorf("proto log decode failed, offset=%d len=%d", decoder.Offset(), len(decoder.Bytes()))
			return
		}
		d.sendProto(protoLog)
	}
}

func (d *Decoder) sendFlow(flow *pb.TaggedFlow) {
	if d.debugEnabled {
		log.Debugf("decoder %d recv flow: %s", d.index, flow)
	}
	d.counter.L4Count++
	l := jsonify.TaggedFlowToLogger(flow, d.shardID, d.platformData)
	if !d.throttler.Send(l) {
		d.counter.L4DropCount++
	}
}

func (d *Decoder) sendProto(proto *pb.AppProtoLogsData) {
	if d.debugEnabled {
		log.Debugf("decoder %d recv proto: %s", d.index, proto)
	}

	d.counter.L7Count++
	drop := int64(0)
	if proto.BaseInfo.Head.Proto < uint32(L7_PROTO_MAX) &&
		d.l7Disableds[proto.BaseInfo.Head.Proto] {
		drop = 1
	} else {
		tapSide := zerodoc.TAPSideEnum(proto.BaseInfo.TapSide).String()
		s := []interface{}{}
		if tapSide == "c" {
			l1 := jsonify.ProtoLogToL7Logger(proto, d.shardID, d.platformData)
			l2 := jsonify.ProtoLogToL7Logger(proto, d.shardID, d.platformData)
			l := l2.(*jsonify.L7Logger)
			l.TapSide = "c-p"
			l.ProcessID0 = l.PodID0
			l.ProcessKName0 = strconv.Itoa(int(l.PodID0))
			s = append(s, l1, l2)
		} else if tapSide == "s" {
			l1 := jsonify.ProtoLogToL7Logger(proto, d.shardID, d.platformData)
			l2 := jsonify.ProtoLogToL7Logger(proto, d.shardID, d.platformData)
			l := l2.(*jsonify.L7Logger)
			l.TapSide = "s-p"
			l.ProcessID0 = l.PodID1
			l.ProcessKName0 = strconv.Itoa(int(l.PodID1))
			s = append(s, l1, l2)
		} else {
			l := jsonify.ProtoLogToL7Logger(proto, d.shardID, d.platformData)
			s = append(s, l)
		}
		for l := range s {
			if !d.throttler.Send(l) {
				d.counter.L7DropCount++
				drop = 1
			}
		}
	}
	proto.Release()

	switch datatype.LogProtoType(proto.BaseInfo.Head.Proto) {
	case datatype.PROTO_HTTP_1, datatype.PROTO_HTTP_2:
		d.counter.L7HTTPCount++
		d.counter.L7HTTPDropCount += drop
	case datatype.PROTO_DNS:
		d.counter.L7DNSCount++
		d.counter.L7DNSDropCount += drop
	case datatype.PROTO_MYSQL:
		d.counter.L7SQLCount++
		d.counter.L7SQLDropCount += drop
	case datatype.PROTO_REDIS:
		d.counter.L7NoSQLCount++
		d.counter.L7NoSQLDropCount += drop
	case datatype.PROTO_DUBBO:
		d.counter.L7RPCCount++
		d.counter.L7RPCDropCount += drop
	case datatype.PROTO_KAFKA:
		d.counter.L7MQCount++
		d.counter.L7MQDropCount += drop
	}
}

func (d *Decoder) flush() {
	if d.throttler != nil {
		d.throttler.Send(nil)
	}
}
