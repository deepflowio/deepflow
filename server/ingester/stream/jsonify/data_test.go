/*
 * Copyright (c) 2022 Yunshan Networks
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

package jsonify

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/metaflowys/metaflow/server/ingester/stream/geo"
	"github.com/metaflowys/metaflow/server/libs/datatype"
	"github.com/metaflowys/metaflow/server/libs/datatype/pb"
	"github.com/metaflowys/metaflow/server/libs/grpc"
)

func TestJsonify(t *testing.T) {
	geo.NewGeoTree()
	info := FlowLogger{
		DataLinkLayer: DataLinkLayer{
			VLAN: 123,
		},
		FlowInfo: FlowInfo{
			L2End0: true,
		},
	}
	b, _ := json.Marshal(info)
	var newInfo FlowLogger
	json.Unmarshal(b, &newInfo)
	if info.VLAN != newInfo.VLAN {
		t.Error("string jsonify failed")
	}
	if info.L2End0 != newInfo.L2End0 {
		t.Error("bool jsonify failed")
	}
}

func TestZeroToNull(t *testing.T) {
	pf := grpc.NewPlatformInfoTable(nil, 0, "", "", "", nil)
	taggedFlow := pb.TaggedFlow{
		Flow: &pb.Flow{
			FlowKey:        &pb.FlowKey{},
			Tunnel:         &pb.TunnelField{},
			MetricsPeerSrc: &pb.FlowMetricsPeer{},
			MetricsPeerDst: &pb.FlowMetricsPeer{},
		},
	}

	flow := TaggedFlowToLogger(&taggedFlow, 0, pf)

	flowByte, _ := json.Marshal(flow)

	print(string(flowByte))

	if strings.Contains(string(flowByte), "\"byte_tx\"") {
		t.Error("rtt zero to null failed")
	}

	if strings.Contains(string(flowByte), "\"rtt\"") {
		t.Error("rtt zero to null failed")
	}
	if flow.EndTime() != 0 {
		t.Error("flow endtime should be 0")
	}
	flow.String()
	flow.Release()
}

func TestParseUint32EpcID(t *testing.T) {
	if r := parseUint32EpcID(32767); r != 32767 {
		t.Errorf("expect 32767, result %v", r)
	}
	if r := parseUint32EpcID(40000); r != 40000 {
		t.Errorf("expect 40000, result %v", r)
	}
	id := datatype.EPC_FROM_DEEPFLOW
	if r := parseUint32EpcID(uint32(id)); r != datatype.EPC_FROM_DEEPFLOW {
		t.Errorf("expect %v, result %v", datatype.EPC_FROM_DEEPFLOW, r)
	}
	id = datatype.EPC_FROM_INTERNET
	if r := parseUint32EpcID(uint32(id)); r != datatype.EPC_FROM_INTERNET {
		t.Errorf("expect %v, result %v", datatype.EPC_FROM_INTERNET, r)
	}
}

func TestProtoLogToHTTPLogger(t *testing.T) {
	appData := &pb.AppProtoLogsData{
		Base: &pb.AppProtoLogsBaseInfo{
			Head: &pb.AppProtoHead{},
		},
	}
	appData.Base.VtapId = 123
	appData.Base.EndTime = uint64(10 * time.Microsecond)
	appData.Base.Head.Proto = uint32(datatype.L7_PROTOCOL_HTTP_1)
	appData.Http = &pb.HttpInfo{}

	pf := grpc.NewPlatformInfoTable(nil, 0, "", "", "", nil)
	httpData := ProtoLogToL7Logger(appData, 0, pf).(*L7Logger)
	if httpData.VtapID != 123 {
		t.Errorf("expect 123, result %v", httpData.VtapID)
	}
	if httpData.EndTime() != 10*time.Microsecond {
		t.Errorf("expect 10000000, result %v", httpData.EndTime())
	}
	httpData.String()
	httpData.Release()
}

func TestProtoLogToDNSLogger(t *testing.T) {
	appData := &pb.AppProtoLogsData{
		Base: &pb.AppProtoLogsBaseInfo{
			Head: &pb.AppProtoHead{},
		},
	}
	appData.Base.TapType = 3
	appData.Base.EndTime = uint64(10 * time.Microsecond)
	appData.Base.Head.Proto = uint32(datatype.L7_PROTOCOL_DNS)
	appData.Dns = &pb.DnsInfo{}

	pf := grpc.NewPlatformInfoTable(nil, 0, "", "", "", nil)
	dnsData := ProtoLogToL7Logger(appData, 0, pf).(*L7Logger)
	if dnsData.TapType != 3 {
		t.Errorf("expect 3, result %v", dnsData.TapType)
	}
	if dnsData.EndTime() != 10*time.Microsecond {
		t.Errorf("expect 10000000, result %v", dnsData.EndTime())
	}
	dnsData.String()
	dnsData.Release()
}
