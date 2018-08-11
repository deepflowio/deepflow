package mapreduce

import (
	"fmt"
	data "gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"sort"
	"testing"
)

func TestMeteringTags(t *testing.T) {
	tm := data.TaggedMetering{
		Metering: data.Metering{
			Timestamp: 10,
			InPort0:   65536,
			VLAN:      10,
			Proto:     58,
			Exporter:  *data.NewIPFromString("127.0.0.1"),
			IPSrc:     *data.NewIPFromString("192.168.0.1"),
			IPDst:     *data.NewIPFromString("192.168.0.2"),
			PortSrc:   10,
			PortDst:   20,
			PktCnt0:   1000,
			PktCnt1:   2000,
			ByteCnt0:  100000,
			ByteCnt1:  200000,
			L3EpcID0:  1,
			L3EpcID1:  2,
		},
		Tag: data.Tag{
			GroupIDs0:     []uint32{1, 2},
			GroupIDs1:     []uint32{3, 4},
			CustomTagIDs0: []uint32{5},
			CustomTagIDs1: []uint32{6},
		},
	}
	//TODO expectedTags 一条一条详细列出来
	expectedTags := []string{"0 1 32772", "0 1 33280", "0 ICMPv6 1 34820", "0 ICMPv6 1 35328", "1 1 32772", "1 1 32784", "1 ICMPv6 1 34820", "1 ICMPv6 1 34832", "10 1 33792", "10 ICMPv6 1 35840", "192.168.0.1 0 1 33025", "192.168.0.1 0 ICMPv6 1 35329", "192.168.0.1 1 1 32785", "192.168.0.1 1 32769", "192.168.0.1 1 ICMPv6 1 34833", "192.168.0.1 10 1 33793", "192.168.0.1 ICMPv6 1 34817", "192.168.0.10 1 33281", "192.168.0.2 0 ICMPv6 1 35329", "192.168.0.2 1 1 33025", "192.168.0.2 1 32769", "192.168.0.2 10 1 33793", "192.168.0.2 2 1 32785", "192.168.0.2 2 ICMPv6 1 34833", "192.168.0.2 ICMPv6 1 34817", "192.168.0.20 1 33281", "2 1 32784", "2 ICMPv6 1 34832", "ICMPv6 1 34816"} //for test, will get the actual flow queue later
	q := queue.OverwriteQueue{}
	processor := MeteringMapProcessor{q}
	tags := processor.MeteringHandler(&tm)

	//if len(tags) != len(expectedTags) {
	//	t.Error("输出文档数不正确")
	//}

	sort.Strings(expectedTags)
	sort.Strings(tags)

	for i := range expectedTags {
		if expectedTags[i] != tags[i] {
			t.Errorf("Tag不正确，应为%#v，实际为%#v", expectedTags, tags)
			break
		}
		fmt.Println(tags[i])
	}
}
