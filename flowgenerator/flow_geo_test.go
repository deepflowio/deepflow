package flowgenerator

import (
	"net"
	"testing"
	"time"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

var (
	testFlowGeo = newFlowGeo()
)

func TestFillGeoInfo(t *testing.T) {
	taggedFlow := &TaggedFlow{}
	taggedFlow.IPSrc = IpToUint32(net.ParseIP("8.8.8.8").To4())
	taggedFlow.IPDst = IpToUint32(net.ParseIP("114.114.114.114").To4())
	taggedFlow.FlowMetricsPeers[FLOW_METRICS_PEER_SRC].L3EpcID = 1
	taggedFlow.FlowMetricsPeers[FLOW_METRICS_PEER_DST].L3EpcID = EPC_FROM_INTERNET
	taggedFlow.PolicyData = &PolicyData{ActionFlags: ACTION_GEO_POSITIONING}
	testFlowGeo.fillGeoInfo(taggedFlow)
	// 查ip_info.go文件获得Country和Region实际值
	country := uint8(5)
	region := uint8(34)
	if taggedFlow.Country != country || taggedFlow.Region != region {
		t.Errorf("taggedFlow.Country is %d, expect %d", taggedFlow.Country, country)
		t.Errorf("taggedFlow.Region is %d, expect %d", taggedFlow.Region, region)
	}
}

func TestNegativeL3EpcIDSrc(t *testing.T) {
	taggedFlow := &TaggedFlow{}
	taggedFlow.IPSrc = IpToUint32(net.ParseIP("8.8.8.8").To4())
	taggedFlow.IPDst = IpToUint32(net.ParseIP("114.114.114.114").To4())
	taggedFlow.FlowMetricsPeers[FLOW_METRICS_PEER_SRC].L3EpcID = EPC_FROM_DEEPFLOW
	taggedFlow.FlowMetricsPeers[FLOW_METRICS_PEER_DST].L3EpcID = 5
	taggedFlow.PolicyData = &PolicyData{ActionFlags: ACTION_GEO_POSITIONING}
	testFlowGeo.fillGeoInfo(taggedFlow)
	// 查ip_info.go文件获得Country和Region实际值
	country := uint8(98)
	region := uint8(0)
	if taggedFlow.Country != country || taggedFlow.Region != region {
		t.Errorf("taggedFlow.Country is %d, expect %d", taggedFlow.Country, country)
		t.Errorf("taggedFlow.Region is %d, expect %d", taggedFlow.Region, region)
	}
}

func TestNegativeL3EpcIDDst(t *testing.T) {
	taggedFlow := &TaggedFlow{}
	taggedFlow.IPSrc = IpToUint32(net.ParseIP("8.8.8.8").To4())
	taggedFlow.IPDst = IpToUint32(net.ParseIP("114.114.114.114").To4())
	taggedFlow.FlowMetricsPeers[FLOW_METRICS_PEER_SRC].L3EpcID = 5
	taggedFlow.FlowMetricsPeers[FLOW_METRICS_PEER_DST].L3EpcID = EPC_FROM_DEEPFLOW
	taggedFlow.PolicyData = &PolicyData{ActionFlags: ACTION_GEO_POSITIONING}
	testFlowGeo.fillGeoInfo(taggedFlow)
	// 查ip_info.go文件获得Country和Region实际值
	country := uint8(5)
	region := uint8(34)
	if taggedFlow.Country != country || taggedFlow.Region != region {
		t.Errorf("taggedFlow.Country is %d, expect %d", taggedFlow.Country, country)
		t.Errorf("taggedFlow.Region is %d, expect %d", taggedFlow.Region, region)
	}
}

func TestNegativeL3EpcIDAll(t *testing.T) {
	taggedFlow := &TaggedFlow{}
	taggedFlow.IPSrc = IpToUint32(net.ParseIP("8.8.8.8").To4())
	taggedFlow.IPDst = IpToUint32(net.ParseIP("114.114.114.114").To4())
	taggedFlow.FlowMetricsPeers[FLOW_METRICS_PEER_SRC].L3EpcID = EPC_FROM_DEEPFLOW
	taggedFlow.FlowMetricsPeers[FLOW_METRICS_PEER_DST].L3EpcID = EPC_FROM_DEEPFLOW
	taggedFlow.PolicyData = &PolicyData{ActionFlags: ACTION_GEO_POSITIONING}
	testFlowGeo.fillGeoInfo(taggedFlow)
	// 查ip_info.go文件获得Country和Region实际值
	country := uint8(98)
	region := uint8(0)
	if taggedFlow.Country != country || taggedFlow.Region != region {
		t.Errorf("taggedFlow.Country is %d, expect %d", taggedFlow.Country, country)
		t.Errorf("taggedFlow.Region is %d, expect %d", taggedFlow.Region, region)
	}
}

func TestFlowGeoInfo(t *testing.T) {
	flowGenerator, inputPacketQueue, flowOutQueue, _ := flowGeneratorInit(0, true)
	flowGenerator.flowMap.FlowGeo = testFlowGeo
	forceReportInterval = 60 * time.Second
	block := &MetaPacketBlock{}

	packet0 := getDefaultPacket()
	packet0.EndpointData.SrcInfo.L3EpcId = 5
	packet0.EndpointData.DstInfo.L3EpcId = EPC_FROM_INTERNET
	block.Metas[block.Count] = *packet0
	block.Count++

	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_RST
	packet1.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet1)
	packet1.EndpointData.SrcInfo.L3EpcId = EPC_FROM_INTERNET
	packet1.EndpointData.DstInfo.L3EpcId = EPC_FROM_INTERNET
	block.Metas[block.Count] = *packet1
	block.Count++
	inputPacketQueue.Put(block)

	flowGenerator.Start()

	taggedFlow := getFromQueue(flowOutQueue).(*TaggedFlow) // 有ticker不能直接Get
	country := uint8(5)
	region := uint8(34)
	if taggedFlow.Country != country || taggedFlow.Region != region {
		t.Errorf("taggedFlow.Country is %d, expect %d", taggedFlow.Country, country)
		t.Errorf("taggedFlow.Region is %d, expect %d", taggedFlow.Region, region)
	}
}

func BenchmarkFillGeoInfo(b *testing.B) {
	taggedFlow := &TaggedFlow{}
	flowMetricsPeerSrc := &taggedFlow.FlowMetricsPeers[FLOW_METRICS_PEER_SRC]
	flowMetricsPeerDst := &taggedFlow.FlowMetricsPeers[FLOW_METRICS_PEER_DST]
	taggedFlow.IPSrc = IpToUint32(net.ParseIP("8.8.8.8").To4())
	taggedFlow.IPDst = IpToUint32(net.ParseIP("114.114.114.114").To4())
	flowMetricsPeerSrc.L3EpcID = 1
	flowMetricsPeerDst.L3EpcID = EPC_FROM_INTERNET
	taggedFlow.PolicyData = &PolicyData{ActionFlags: ACTION_GEO_POSITIONING}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		flowMetricsPeerSrc.L3EpcID, flowMetricsPeerDst.L3EpcID = flowMetricsPeerDst.L3EpcID, flowMetricsPeerSrc.L3EpcID
		testFlowGeo.fillGeoInfo(taggedFlow)
	}
}
