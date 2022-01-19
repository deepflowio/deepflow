package decoder

import (
	"strconv"

	logging "github.com/op/go-logging"

	"gitlab.yunshan.net/yunshan/droplet-libs/codec"
	"gitlab.yunshan.net/yunshan/droplet-libs/datatype"
	"gitlab.yunshan.net/yunshan/droplet-libs/datatype/pb"
	"gitlab.yunshan.net/yunshan/droplet-libs/grpc"
	"gitlab.yunshan.net/yunshan/droplet-libs/queue"
	"gitlab.yunshan.net/yunshan/droplet-libs/receiver"
	"gitlab.yunshan.net/yunshan/droplet-libs/stats"
	"gitlab.yunshan.net/yunshan/droplet-libs/utils"
	"gitlab.yunshan.net/yunshan/droplet/stream/common"
	"gitlab.yunshan.net/yunshan/droplet/stream/jsonify"
	"gitlab.yunshan.net/yunshan/droplet/stream/throttler"
)

var log = logging.MustGetLogger("stream.decoder")

const (
	BUFFER_SIZE = 1024
)

type Counter struct {
	RawCount         int64 `statsd:"raw-count"`
	L4Count          int64 `statsd:"l4-count"`
	L4DropCount      int64 `statsd:"l4-drop-count"`
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
	throttlers   [common.FLOWLOG_ID_MAX]*throttler.ThrottlingQueue
	debugEnabled bool

	counter *Counter
	utils.Closable
}

func NewDecoder(
	index, msgType, shardID int,
	platformData *grpc.PlatformInfoTable,
	inQueue queue.QueueReader,
	throttlers [common.FLOWLOG_ID_MAX]*throttler.ThrottlingQueue,
) *Decoder {
	return &Decoder{
		index:        index,
		msgType:      msgType,
		shardID:      shardID,
		platformData: platformData,
		inQueue:      inQueue,
		throttlers:   throttlers,
		debugEnabled: log.IsEnabledFor(logging.DEBUG),
		counter:      &Counter{},
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
	pbTaggedFlow := &pb.TaggedFlow{}
	for !decoder.IsEnd() {
		pbTaggedFlow.Reset()
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
	if !d.throttlers[common.L4_FLOW_ID].Send(l) {
		d.counter.L4DropCount++
	}
}

type decodeFunc func(*pb.AppProtoLogsData, int, *grpc.PlatformInfoTable) interface{}

var decoderFuncs = []decodeFunc{
	datatype.PROTO_HTTP:  jsonify.ProtoLogToHTTPLogger,
	datatype.PROTO_DNS:   jsonify.ProtoLogToDNSLogger,
	datatype.PROTO_MYSQL: jsonify.ProtoLogToSQLLogger,
	datatype.PROTO_REDIS: jsonify.ProtoLogToNoSQLLogger,
	datatype.PROTO_DUBBO: jsonify.ProtoLogToRPCLogger,
	datatype.PROTO_KAFKA: jsonify.ProtoLogToMQLogger,
}

var throttleIDs = []common.FlowLogID{
	datatype.PROTO_HTTP:  common.L7_HTTP_ID,
	datatype.PROTO_DNS:   common.L7_DNS_ID,
	datatype.PROTO_MYSQL: common.L7_SQL_ID,
	datatype.PROTO_REDIS: common.L7_NOSQL_ID,
	datatype.PROTO_DUBBO: common.L7_RPC_ID,
	datatype.PROTO_KAFKA: common.L7_MQ_ID,
}

func (d *Decoder) sendProto(proto *pb.AppProtoLogsData) {
	if d.debugEnabled {
		log.Debugf("decoder %d recv proto: %s", d.index, proto)
	}

	protoHead := proto.BaseInfo.Head
	if int(protoHead.Proto) >= len(decoderFuncs) {
		log.Warningf("invalid proto.Proto %d %s", protoHead.Proto, proto)
	}

	decoder := decoderFuncs[protoHead.Proto]
	if decoder == nil {
		d.counter.ErrorCount++
		log.Debugf("proto(%s) decoder is not exist", protoHead.Proto)
		return
	}

	l := decoder(proto, d.shardID, d.platformData)
	throttleID := throttleIDs[protoHead.Proto]
	var drop int64
	if !d.throttlers[throttleID].Send(l) {
		drop++
	}
	switch datatype.LogProtoType(protoHead.Proto) {
	case datatype.PROTO_HTTP:
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
	for _, throttler := range d.throttlers {
		if throttler != nil {
			throttler.Send(nil)

		}
	}
}
