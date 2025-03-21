/*
 * Copyright (c) 2024 Yunshan Networks
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
	"io"
	"strconv"
	"time"

	"github.com/golang/protobuf/proto"
	logging "github.com/op/go-logging"
	v1 "go.opentelemetry.io/proto/otlp/trace/v1"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/exporters"
	exportcommon "github.com/deepflowio/deepflow/server/ingester/exporters/common"
	exportconfig "github.com/deepflowio/deepflow/server/ingester/exporters/config"
	flowlogcommon "github.com/deepflowio/deepflow/server/ingester/flow_log/common"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/config"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/dbwriter"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/log_data"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/log_data/dd_import"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/log_data/sw_import"
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
	index               int
	msgType             datatype.MessageType
	dataSourceID        uint32
	platformData        *grpc.PlatformInfoTable
	inQueue             queue.QueueReader
	throttler           *throttler.ThrottlingQueue
	flowTagWriter       *flow_tag.FlowTagWriter
	appServiceTagWriter *flow_tag.AppServiceTagWriter
	spanWriter          *dbwriter.SpanWriter
	spanBuf             []interface{}
	exporters           *exporters.Exporters
	cfg                 *config.Config
	debugEnabled        bool

	agentId, orgId, teamId uint16

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
	appServiceTagWriter *flow_tag.AppServiceTagWriter,
	spanWriter *dbwriter.SpanWriter,
	exporters *exporters.Exporters,
	cfg *config.Config,
) *Decoder {
	return &Decoder{
		index:               index,
		msgType:             msgType,
		dataSourceID:        exportconfig.FlowLogMessageToDataSourceID(msgType),
		platformData:        platformData,
		inQueue:             inQueue,
		throttler:           throttler,
		flowTagWriter:       flowTagWriter,
		appServiceTagWriter: appServiceTagWriter,
		spanWriter:          spanWriter,
		spanBuf:             make([]interface{}, 0, BUFFER_SIZE),
		exporters:           exporters,
		cfg:                 cfg,
		debugEnabled:        log.IsEnabledFor(logging.DEBUG),
		fieldsBuf:           make([]interface{}, 0, 64),
		fieldValuesBuf:      make([]interface{}, 0, 64),
		counter:             &Counter{},
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
	pbThirdPartyTrace := &pb.ThirdPartyTrace{}
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
			d.agentId, d.orgId, d.teamId = recvBytes.VtapID, uint16(recvBytes.OrgID), uint16(recvBytes.TeamID)
			switch d.msgType {
			case datatype.MESSAGE_TYPE_PROTOCOLLOG:
				d.handleProtoLog(decoder)
			case datatype.MESSAGE_TYPE_TAGGEDFLOW:
				d.handleTaggedFlow(decoder, pbTaggedFlow)
			case datatype.MESSAGE_TYPE_OPENTELEMETRY:
				d.handleOpenTelemetry(decoder, pbTracesData, false)
			case datatype.MESSAGE_TYPE_OPENTELEMETRY_COMPRESSED:
				d.handleOpenTelemetry(decoder, pbTracesData, true)
			case datatype.MESSAGE_TYPE_PACKETSEQUENCE:
				d.handleL4Packet(decoder)
			case datatype.MESSAGE_TYPE_SKYWALKING:
				d.handleSkyWalking(decoder, pbThirdPartyTrace, false)
			case datatype.MESSAGE_TYPE_DATADOG:
				d.handleDatadog(decoder, pbThirdPartyTrace, false)
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

	return io.ReadAll(reader)
}

func (d *Decoder) handleOpenTelemetry(decoder *codec.SimpleDecoder, pbTracesData *v1.TracesData, compressed bool) {
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
		d.sendOpenMetetry(pbTracesData)
	}
}

func (d *Decoder) sendOpenMetetry(tracesData *v1.TracesData) {
	if d.debugEnabled {
		log.Debugf("decoder %d vtap %d recv otel: %s", d.index, d.agentId, tracesData)
	}
	d.counter.Count++
	ls := log_data.OTelTracesDataToL7FlowLogs(d.agentId, d.orgId, d.teamId, tracesData, d.platformData, d.cfg)
	for _, l := range ls {
		l.AddReferenceCount()
		if !d.throttler.SendWithThrottling(l) {
			d.counter.DropCount++
		} else {
			d.fieldsBuf, d.fieldValuesBuf = d.fieldsBuf[:0], d.fieldValuesBuf[:0]
			l.GenerateNewFlowTags(d.flowTagWriter.Cache)
			d.flowTagWriter.WriteFieldsAndFieldValuesInCache()
			d.appServiceTagWrite(l)
			d.spanWrite(l)
		}
		l.Release()
	}
}

func (d *Decoder) handleSkyWalking(decoder *codec.SimpleDecoder, pbThirdPartyTrace *pb.ThirdPartyTrace, compressed bool) {
	var err error
	buffer := log_data.GetBuffer()
	for !decoder.IsEnd() {
		pbThirdPartyTrace.Reset()
		pbThirdPartyTrace.Data = buffer.Bytes()
		bytes := decoder.ReadBytes()
		if len(bytes) > 0 {
			// universal compression
			if compressed {
				bytes, err = decompressOpenTelemetry(bytes)
			}
			if err == nil {
				err = proto.Unmarshal(bytes, pbThirdPartyTrace)
			}
		}
		if decoder.Failed() || err != nil {
			if d.counter.ErrorCount == 0 {
				log.Errorf("skywalking data decode failed, offset=%d len=%d err: %s", decoder.Offset(), len(decoder.Bytes()), err)
			}
			d.counter.ErrorCount++
			continue
		}
		d.sendSkyWalking(pbThirdPartyTrace.Data, pbThirdPartyTrace.PeerIp, pbThirdPartyTrace.Uri)
		log_data.PutBuffer(buffer)
	}
}

func (d *Decoder) sendSkyWalking(segmentData, peerIP []byte, uri string) {
	if d.debugEnabled {
		log.Debugf("decoder %d vtap %d recv skywalking data length: %d", d.index, d.agentId, len(segmentData))
	}
	d.counter.Count++
	ls := sw_import.SkyWalkingDataToL7FlowLogs(d.agentId, d.orgId, d.teamId, segmentData, peerIP, uri, d.platformData, d.cfg)
	for _, l := range ls {
		l.AddReferenceCount()
		if !d.throttler.SendWithThrottling(l) {
			d.counter.DropCount++
		} else {
			d.fieldsBuf, d.fieldValuesBuf = d.fieldsBuf[:0], d.fieldValuesBuf[:0]
			l.GenerateNewFlowTags(d.flowTagWriter.Cache)
			d.flowTagWriter.WriteFieldsAndFieldValuesInCache()
			d.appServiceTagWrite(l)
			d.spanWrite(l)
		}
		l.Release()
	}
}

func (d *Decoder) handleDatadog(decoder *codec.SimpleDecoder, pbThirdPartyTrace *pb.ThirdPartyTrace, compressed bool) {
	var err error
	buffer := log_data.GetBuffer()
	for !decoder.IsEnd() {
		pbThirdPartyTrace.Reset()
		pbThirdPartyTrace.Data = buffer.Bytes()
		bytes := decoder.ReadBytes()
		if len(bytes) > 0 {
			// universal compression
			if compressed {
				bytes, err = decompressOpenTelemetry(bytes)
			}
			if err == nil {
				err = proto.Unmarshal(bytes, pbThirdPartyTrace)
			}
		}
		if decoder.Failed() || err != nil {
			if d.counter.ErrorCount == 0 {
				log.Errorf("datadog data decode failed, offset=%d len=%d err: %s", decoder.Offset(), len(decoder.Bytes()), err)
			}
			d.counter.ErrorCount++
			continue
		}
		d.sendDatadog(pbThirdPartyTrace)
		log_data.PutBuffer(buffer)
	}
}

func (d *Decoder) sendDatadog(ddogData *pb.ThirdPartyTrace) {
	if d.debugEnabled {
		log.Debugf("decoder %d vtap %d recv datadog data length: %d", d.index, d.agentId, len(ddogData.Data))
	}
	d.counter.Count++
	ls := dd_import.DDogDataToL7FlowLogs(d.agentId, d.orgId, d.teamId, ddogData, d.platformData, d.cfg)
	for _, l := range ls {
		l.AddReferenceCount()
		if !d.throttler.SendWithThrottling(l) {
			d.counter.DropCount++
		} else {
			d.fieldsBuf, d.fieldValuesBuf = d.fieldsBuf[:0], d.fieldValuesBuf[:0]
			l.GenerateNewFlowTags(d.flowTagWriter.Cache)
			d.flowTagWriter.WriteFieldsAndFieldValuesInCache()
			d.appServiceTagWrite(l)
			d.spanWrite(l)
		}
		l.Release()
	}
}

func (d *Decoder) handleL4Packet(decoder *codec.SimpleDecoder) {
	for !decoder.IsEnd() {
		l4Packet, err := log_data.DecodePacketSequence(d.agentId, d.orgId, d.teamId, decoder)
		if decoder.Failed() || err != nil {
			if d.counter.ErrorCount == 0 {
				log.Errorf("packet sequence decode failed, offset=%d len=%d, err: %s", decoder.Offset(), len(decoder.Bytes()), err)
			}
			l4Packet.Release()
			d.counter.ErrorCount++
			return
		}

		if d.debugEnabled {
			log.Debugf("decoder %d vtap %d recv l4 packet: %s", d.index, d.agentId, l4Packet)
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
	l := log_data.TaggedFlowToL4FlowLog(d.orgId, d.teamId, flow, d.platformData)

	if l.HitPcapPolicy() {
		d.export(l)
		d.throttler.SendWithoutThrottling(l)
	} else {
		l.AddReferenceCount()
		if !d.throttler.SendWithThrottling(l) {
			d.counter.DropCount++
		} else {
			d.export(l)
		}
		l.Release()
	}
}

func (d *Decoder) export(l exportcommon.ExportItem) {
	if d.exporters != nil {
		d.exporters.Put(d.dataSourceID, d.index, l)
	}
}

func (d *Decoder) spanWrite(l *log_data.L7FlowLog) {
	if d.spanWriter == nil {
		return
	}

	if l == nil {
		if len(d.spanBuf) == 0 {
			return
		}
		d.spanWriter.Put(d.spanBuf)
		d.spanBuf = d.spanBuf[:0]
		return
	}

	if (l.SignalSource == uint16(datatype.SIGNAL_SOURCE_EBPF) ||
		l.SignalSource == uint16(datatype.SIGNAL_SOURCE_OTEL)) && l.TraceId != "" {
		l.AddReferenceCount()
		d.spanBuf = append(d.spanBuf, (*dbwriter.SpanWithTraceID)(l))
		if len(d.spanBuf) >= BUFFER_SIZE {
			d.spanWriter.Put(d.spanBuf)
			d.spanBuf = d.spanBuf[:0]
		}
	}
}

func (d *Decoder) appServiceTagWrite(l *log_data.L7FlowLog) {
	if d.appServiceTagWriter == nil {
		return
	}
	if l.AppService == "" && l.AppInstance == "" {
		return
	}
	d.appServiceTagWriter.Write(l.Time, flowlogcommon.L7_FLOW_ID.String(), l.AppService, l.AppInstance, l.OrgId, l.TeamID)
}

func (d *Decoder) sendProto(proto *pb.AppProtoLogsData) {
	if d.debugEnabled {
		log.Debugf("decoder %d recv proto: %s", d.index, proto)
	}

	l := log_data.ProtoLogToL7FlowLog(d.orgId, d.teamId, proto, d.platformData, d.cfg)
	l.AddReferenceCount()
	sent := d.throttler.SendWithThrottling(l)
	if sent {
		if d.flowTagWriter != nil {
			d.fieldsBuf, d.fieldValuesBuf = d.fieldsBuf[:0], d.fieldValuesBuf[:0]
			l.GenerateNewFlowTags(d.flowTagWriter.Cache)
			d.flowTagWriter.WriteFieldsAndFieldValuesInCache()
		}
		d.appServiceTagWrite(l)
		d.export(l)
		d.spanWrite(l)
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
	if d.spanWriter != nil {
		d.spanWrite(nil)
	}
}
