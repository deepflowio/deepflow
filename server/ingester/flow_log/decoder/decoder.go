/*
 * Copyright (c) 2023 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package decoder

import (
	"bytes"
	"compress/zlib"
	"io/ioutil"
	"strconv"
	"time"

	"github.com/golang/protobuf/proto"
	logging "github.com/op/go-logging"
	v1 "go.opentelemetry.io/proto/otlp/trace/v1"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/config"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/exporters"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/log_data"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/throttler"
	"github.com/deepflowio/deepflow/server/ingester/flow_tag"
	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/datatype/pb"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/receiver"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

var log = logging.MustGetLogger("flow_log.decoder")

const (
	BUFFER_SIZE  = 1024
	L7_PROTO_MAX = datatype.L7_PROTOCOL_DNS + 1
)

type Counter struct {
	RawCount         int64 `statsd:"raw-count"`
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
	Count            int64 `statsd:"count"`
	DropCount        int64 `statsd:"drop-count"`

	TotalTime int64 `statsd:"total-time"`
	AvgTime   int64 `statsd:"avg-time"`
}

type Decoder struct {
	index         int
	msgType       datatype.MessageType
	platformData  *grpc.PlatformInfoTable
	inQueue       queue.QueueReader
	throttler     *throttler.ThrottlingQueue
	flowTagWriter *flow_tag.FlowTagWriter
	exporters     *exporters.Exporters
	cfg           *config.Config
	debugEnabled  bool

	fieldsBuf      []interface{}
	fieldValuesBuf []interface{}
	counter        *Counter
	lastCounter    Counter // for OTLP debug
	utils.Closable
}

func NewDecoder(
	index int, msgType datatype.MessageType,
	platformData *grpc.PlatformInfoTable,
	inQueue queue.QueueReader,
	throttler *throttler.ThrottlingQueue,
	flowTagWriter *flow_tag.FlowTagWriter,
	exporters *exporters.Exporters,
	cfg *config.Config,
) *Decoder {
	return &Decoder{
		index:          index,
		msgType:        msgType,
		platformData:   platformData,
		inQueue:        inQueue,
		throttler:      throttler,
		flowTagWriter:  flowTagWriter,
		exporters:      exporters,
		cfg:            cfg,
		debugEnabled:   log.IsEnabledFor(logging.DEBUG),
		fieldsBuf:      make([]interface{}, 0, 64),
		fieldValuesBuf: make([]interface{}, 0, 64),
		counter:        &Counter{},
	}
}

func (d *Decoder) GetCounter() interface{} {
	var counter *Counter
	counter, d.counter = d.counter, &Counter{}
	if counter.Count > 0 {
		counter.AvgTime = counter.TotalTime / counter.Count
	}
	d.lastCounter = *counter
	return counter
}

func (d *Decoder) GetLastCounter() *Counter {
	return &d.lastCounter
}

func (d *Decoder) Run() {
	common.RegisterCountableForIngester("decoder", d, stats.OptionStatTags{
		"thread":   strconv.Itoa(d.index),
		"msg_type": d.msgType.String()})
	buffer := make([]interface{}, BUFFER_SIZE)
	decoder := &codec.SimpleDecoder{}
	pbTaggedFlow := pb.NewTaggedFlow()
	pbTracesData := &v1.TracesData{}
	for {
		n := d.inQueue.Gets(buffer)
		start := time.Now()
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
			switch d.msgType {
			case datatype.MESSAGE_TYPE_PROTOCOLLOG:
				d.handleProtoLog(decoder)
			case datatype.MESSAGE_TYPE_TAGGEDFLOW:
				d.handleTaggedFlow(decoder, pbTaggedFlow)
			case datatype.MESSAGE_TYPE_OPENTELEMETRY:
				d.handleOpenTelemetry(recvBytes.VtapID, decoder, pbTracesData, false)
			case datatype.MESSAGE_TYPE_OPENTELEMETRY_COMPRESSED:
				d.handleOpenTelemetry(recvBytes.VtapID, decoder, pbTracesData, true)
			case datatype.MESSAGE_TYPE_PACKETSEQUENCE:
				d.handleL4Packet(recvBytes.VtapID, decoder)
			default:
				log.Warningf("unknown msg type: %d", d.msgType)

			}
			receiver.ReleaseRecvBuffer(recvBytes)
		}
		d.counter.TotalTime += int64(time.Since(start))
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

func decompressOpenTelemetry(compressed []byte) ([]byte, error) {
	reader, err := zlib.NewReader(bytes.NewReader(compressed))
	defer reader.Close()
	if err != nil {
		return nil, err
	}

	return ioutil.ReadAll(reader)
}

func (d *Decoder) handleOpenTelemetry(vtapID uint16, decoder *codec.SimpleDecoder, pbTracesData *v1.TracesData, compressed bool) {
	var err error
	for !decoder.IsEnd() {
		pbTracesData.Reset()
		bytes := decoder.ReadBytes()
		if len(bytes) > 0 {
			if compressed {
				bytes, err = decompressOpenTelemetry(bytes)
			}
			if err == nil {
				err = proto.Unmarshal(bytes, pbTracesData)
			}
		}
		if decoder.Failed() || err != nil {
			if d.counter.ErrorCount == 0 {
				log.Errorf("OpenTelemetry log decode failed, offset=%d len=%d err: %s", decoder.Offset(), len(decoder.Bytes()), err)
			}
			d.counter.ErrorCount++
			return
		}
		d.sendOpenMetetry(vtapID, pbTracesData)
	}
}

func (d *Decoder) sendOpenMetetry(vtapID uint16, tracesData *v1.TracesData) {
	if d.debugEnabled {
		log.Debugf("decoder %d vtap %d recv otel: %s", d.index, vtapID, tracesData)
	}
	d.counter.Count++
	ls := log_data.OTelTracesDataToL7FlowLogs(vtapID, tracesData, d.platformData, d.cfg)
	for _, l := range ls {
		l.AddReferenceCount()
		if !d.throttler.SendWithThrottling(l) {
			d.counter.DropCount++
		} else {
			d.fieldsBuf, d.fieldValuesBuf = d.fieldsBuf[:0], d.fieldValuesBuf[:0]
			l.GenerateNewFlowTags(d.flowTagWriter.Cache)
			d.flowTagWriter.WriteFieldsAndFieldValuesInCache()
		}
		l.Release()
	}
}

func (d *Decoder) handleL4Packet(vtapID uint16, decoder *codec.SimpleDecoder) {
	for !decoder.IsEnd() {
		l4Packet, err := log_data.DecodePacketSequence(decoder, vtapID)
		if decoder.Failed() || err != nil {
			if d.counter.ErrorCount == 0 {
				log.Errorf("packet sequence decode failed, offset=%d len=%d, err: %s", decoder.Offset(), len(decoder.Bytes()), err)
			}
			l4Packet.Release()
			d.counter.ErrorCount++
			return
		}

		if d.debugEnabled {
			log.Debugf("decoder %d vtap %d recv l4 packet: %s", d.index, vtapID, l4Packet)
		}
		d.counter.Count++
		d.throttler.SendWithoutThrottling(l4Packet)
	}
}

func (d *Decoder) sendFlow(flow *pb.TaggedFlow) {
	if d.debugEnabled {
		log.Debugf("decoder %d recv flow: %s", d.index, flow)
	}
	d.counter.Count++
	l := log_data.TaggedFlowToL4FlowLog(flow, d.platformData)

	if l.HitPcapPolicy() {
		d.throttler.SendWithoutThrottling(l)
	} else {
		if !d.throttler.SendWithThrottling(l) {
			d.counter.DropCount++
		}
	}
}

func (d *Decoder) export(l *log_data.L7FlowLog) {
	if d.exporters != nil {
		d.exporters.Put(l, d.index)
	}
}

func (d *Decoder) sendProto(proto *pb.AppProtoLogsData) {
	if d.debugEnabled {
		log.Debugf("decoder %d recv proto: %s", d.index, proto)
	}

	l := log_data.ProtoLogToL7FlowLog(proto, d.platformData, d.cfg)
	l.AddReferenceCount()
	sent := d.throttler.SendWithThrottling(l)
	if sent {
		if d.flowTagWriter != nil {
			d.fieldsBuf, d.fieldValuesBuf = d.fieldsBuf[:0], d.fieldValuesBuf[:0]
			l.GenerateNewFlowTags(d.flowTagWriter.Cache)
			d.flowTagWriter.WriteFieldsAndFieldValuesInCache()
		}
		d.export(l)
	}
	d.updateCounter(datatype.L7Protocol(proto.Base.Head.Proto), !sent)
	l.Release()
	proto.Release()

}

func (d *Decoder) updateCounter(l7Protocol datatype.L7Protocol, dropped bool) {
	d.counter.Count++
	drop := int64(0)
	if dropped {
		d.counter.DropCount++
		drop = 1
	}
	switch l7Protocol {
	case datatype.L7_PROTOCOL_HTTP_1, datatype.L7_PROTOCOL_HTTP_2:
		d.counter.L7HTTPCount++
		d.counter.L7HTTPDropCount += drop
	case datatype.L7_PROTOCOL_DNS:
		d.counter.L7DNSCount++
		d.counter.L7DNSDropCount += drop
	case datatype.L7_PROTOCOL_MYSQL, datatype.L7_PROTOCOL_POSTGRE:
		d.counter.L7SQLCount++
		d.counter.L7SQLDropCount += drop
	case datatype.L7_PROTOCOL_REDIS:
		d.counter.L7NoSQLCount++
		d.counter.L7NoSQLDropCount += drop
	case datatype.L7_PROTOCOL_DUBBO:
		d.counter.L7RPCCount++
		d.counter.L7RPCDropCount += drop
	case datatype.L7_PROTOCOL_MQTT:
		d.counter.L7MQCount++
		d.counter.L7MQDropCount += drop
	}
}

func (d *Decoder) flush() {
	if d.throttler != nil {
		d.throttler.SendWithThrottling(nil)
		d.throttler.SendWithoutThrottling(nil)
	}
	d.export(nil)
}
