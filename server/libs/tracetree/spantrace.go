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

package tracetree

import (
	"fmt"
	"net"

	"github.com/deepflowio/deepflow/server/libs/codec"
	flow_metrics "github.com/deepflowio/deepflow/server/libs/flow-metrics"
	"github.com/deepflowio/deepflow/server/libs/pool"
)

const SPAN_TRACE_VERSION_0x12 = 0x12 // before 20251027
const SPAN_TRACE_VERSION = 0x13

type SpanTrace struct {
	Time          uint32 // not store, easy to use when calculating
	QuerierRegion string // not store, easy to use when calculating
	TraceId2      string // not store, easy to use when calculating

	EndTimeUsPart uint32 // The microsecond part less than 1 second

	CaptureNic         uint32
	CaptureNicType     uint8
	CaptureNetworkType uint8
	AutoServiceType0   uint8
	AutoServiceType1   uint8
	AutoServiceID0     uint32
	AutoServiceID1     uint32
	IsIPv4             bool
	IP40               uint32
	IP60               net.IP
	IP41               uint32
	IP61               net.IP

	ProcessId0             uint32
	ProcessId1             uint32
	AgentId                uint16
	ObservationPoint       string
	ReqTcpSeq              uint32
	RespTcpSeq             uint32
	XRequestId0            string
	XRequestId1            string
	SpanId                 string
	ParentSpanId           string
	AppService             string
	Topic                  string // only valid when is Kafka protocol, from l7FlowLog RequestDomain
	RequestType            string // only valid when is Kafka protocol
	SyscallTraceIDRequest  uint64
	SyscallTraceIDResponse uint64

	ResponseDuration uint64
	ResponseStatus   uint8
	Type             uint8
}

func (t *SpanTrace) Decode(decoder *codec.SimpleDecoder) error {
	version := decoder.ReadU8()
	if version != SPAN_TRACE_VERSION {
		return fmt.Errorf("span trace data version is %d expect version is %d", version, SPAN_TRACE_VERSION)
	}
	t.EndTimeUsPart = decoder.ReadU32()
	t.CaptureNic = decoder.ReadVarintU32()
	t.CaptureNicType = decoder.ReadU8()
	t.CaptureNetworkType = decoder.ReadU8()
	t.AutoServiceType0 = decoder.ReadU8()
	t.AutoServiceType1 = decoder.ReadU8()
	t.AutoServiceID0 = decoder.ReadVarintU32()
	t.AutoServiceID1 = decoder.ReadVarintU32()
	t.IsIPv4 = decoder.ReadBool()
	if t.IsIPv4 {
		t.IP40 = decoder.ReadU32()
		t.IP41 = decoder.ReadU32()
	} else {
		t.IP60 = make([]byte, 16)
		t.IP61 = make([]byte, 16)
		decoder.ReadIPv6(t.IP60)
		decoder.ReadIPv6(t.IP61)
	}
	t.ProcessId0 = decoder.ReadVarintU32()
	t.ProcessId1 = decoder.ReadVarintU32()
	t.AgentId = decoder.ReadU16()
	t.ObservationPoint = flow_metrics.TAPSideEnum(decoder.ReadU8()).String()
	t.ReqTcpSeq = decoder.ReadVarintU32()
	t.RespTcpSeq = decoder.ReadVarintU32()
	t.XRequestId0 = decoder.ReadString255()
	t.XRequestId1 = decoder.ReadString255()
	t.SpanId = decoder.ReadString255()
	t.ParentSpanId = decoder.ReadString255()
	t.AppService = decoder.ReadString255()
	t.Topic = decoder.ReadString255()
	t.RequestType = decoder.ReadString255()

	t.SyscallTraceIDRequest = decoder.ReadVarintU64()
	t.SyscallTraceIDResponse = decoder.ReadVarintU64()
	t.ResponseDuration = decoder.ReadVarintU64()
	t.ResponseStatus = decoder.ReadU8()
	t.Type = decoder.ReadU8()
	if decoder.Failed() {
		return fmt.Errorf("span trace decode failed, offset is %d, buf length is %d ", decoder.Offset(), len(decoder.Bytes()))
	}
	return nil

}

var poolSpanTrace = pool.NewLockFreePool(func() *SpanTrace {
	return new(SpanTrace)
})

func AcquireSpanTrace() *SpanTrace {
	return poolSpanTrace.Get()
}

func ReleaseSpanTrace(t *SpanTrace) {
	if t == nil {
		return
	}
	*t = SpanTrace{}
	poolSpanTrace.Put(t)
}
