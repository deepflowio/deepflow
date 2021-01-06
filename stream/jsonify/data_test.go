package jsonify

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet/stream/geo"
	pf "gitlab.x.lan/yunshan/droplet/stream/platformdata"
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
	pf.New(nil, 0, "stream", nil)
	taggedFlow := datatype.TaggedFlow{}

	flow := TaggedFlowToLogger(&taggedFlow)

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
	appData := &datatype.AppProtoLogsData{}
	appData.VtapId = 123
	appData.Timestamp = 10 * time.Microsecond
	appData.Proto = datatype.PROTO_HTTP
	appData.Detail = &datatype.HTTPInfo{}

	httpData := ProtoLogToHTTPLogger(appData)
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
	appData := &datatype.AppProtoLogsData{}
	appData.TapType = 3
	appData.Timestamp = 10 * time.Microsecond
	appData.Proto = datatype.PROTO_HTTP
	appData.Detail = &datatype.DNSInfo{}

	dnsData := ProtoLogToDNSLogger(appData)
	if dnsData.TapType != 3 {
		t.Errorf("expect 3, result %v", dnsData.TapType)
	}
	if dnsData.EndTime() != 10*time.Microsecond {
		t.Errorf("expect 10000000, result %v", dnsData.EndTime())
	}
	dnsData.String()
	dnsData.Release()
}
