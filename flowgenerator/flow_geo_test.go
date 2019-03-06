package flowgenerator

import (
	"net"
	"testing"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

func TestFillGeoInfo(t *testing.T) {
	taggedFlow := &TaggedFlow{}
	taggedFlow.IPSrc = IpToUint32(net.ParseIP("8.8.8.8").To4())
	taggedFlow.IPDst = IpToUint32(net.ParseIP("114.114.114.114").To4())
	taggedFlow.FlowMetricsPeerSrc.L3EpcID = 1
	taggedFlow.FlowMetricsPeerDst.L3EpcID = 0
	taggedFlow.PolicyData = &PolicyData{ActionFlags: ACTION_GEO_POSITIONING}
	innerFlowGeo.fillGeoInfo(taggedFlow)
	// 查ip_info.go文件获得Country和Region实际值
	country := uint8(5)
	region := uint8(34)
	if taggedFlow.Country != country || taggedFlow.Region != region {
		t.Errorf("taggedFlow.Country is %d, expect %d", taggedFlow.Country, country)
		t.Errorf("taggedFlow.Region is %d, expect %d", taggedFlow.Region, region)
	}
}

func BenchmarkFillGeoInfo(b *testing.B) {
	taggedFlow := &TaggedFlow{}
	taggedFlow.IPSrc = IpToUint32(net.ParseIP("8.8.8.8").To4())
	taggedFlow.IPDst = IpToUint32(net.ParseIP("114.114.114.114").To4())
	taggedFlow.FlowMetricsPeerSrc.L3EpcID = 1
	taggedFlow.FlowMetricsPeerDst.L3EpcID = 0
	taggedFlow.PolicyData = &PolicyData{ActionFlags: ACTION_GEO_POSITIONING}
	for i := 0; i < b.N; i++ {
		taggedFlow.FlowMetricsPeerSrc.L3EpcID, taggedFlow.FlowMetricsPeerDst.L3EpcID = taggedFlow.FlowMetricsPeerDst.L3EpcID, taggedFlow.FlowMetricsPeerSrc.L3EpcID
		innerFlowGeo.fillGeoInfo(taggedFlow)
	}
}
