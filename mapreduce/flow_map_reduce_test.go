package mapreduce

import (
	"fmt"
	data "gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"sort"
	"testing"
)

func TestTags(t *testing.T) {
	tcpPerfStat := data.TcpPerfStat{
		RTTSyn:            1000,
		RTT:               1000,
		RTTAvg:            1000,
		SynRetransCnt0:    1000,
		SynRetransCnt1:    1000,
		RetransCnt0:       1000,
		RetransCnt1:       1000,
		TotalRetransCnt:   1000,
		ZeroWndCnt0:       1000,
		ZeroWndCnt1:       1000,
		TotalZeroWndCnt:   1000,
		SlowStartCnt0:     1000,
		SlowStartCnt1:     1000,
		TotalSlowStartCnt: 1000,
		PshUrgCnt0:        1000,
		PshUrgCnt1:        1000,
		TotalPshUrgCnt:    1000,
	}
	flow := data.TaggedFlow{
		Flow: data.Flow{
			StartTime: 1533376467,
			Host:      *data.NewIPFromString("127.0.0.1"),
			CloseType: 2,
			FlowKey: data.FlowKey{
				InPort0: 196608,
				IPSrc:   *data.NewIPFromString("192.168.0.1"),
				IPDst:   *data.NewIPFromString("192.168.0.2"),
				Proto:   58,
				PortSrc: 10,
				PortDst: 20,
			},
			VLAN:   10,
			MACSrc: *data.NewMACAddrFromString("11:22:33:44:55:66"),
			MACDst: *data.NewMACAddrFromString("11:22:33:33:55:66"),

			PktCnt0:       1000,
			PktCnt1:       2000,
			ByteCnt0:      100000,
			ByteCnt1:      200000,
			TotalByteCnt0: 100000,
			TotalByteCnt1: 200000,
			TotalPktCnt0:  1000,
			TotalPktCnt1:  2000,
			L3EpcID0:      1,
			L3EpcID1:      2,
			L3DeviceType0: 1,
			L3DeviceType1: 2,
			L3DeviceID0:   3,
			L3DeviceID1:   5,

			EpcID0:      6,
			EpcID1:      6,
			DeviceType0: 8,
			DeviceType1: 8,
			DeviceID0:   9,
			DeviceID1:   9,

			IsL2End0: true,
			IsL2End1: true,
			IsL3End0: true,
			IsL3End1: true,
		},
	}
	flow.TcpPerfStat = &tcpPerfStat
	//for test, will get the actual flow queue later
	q := queue.OverwriteQueue{}
	processor := MapProcessor{q}
	tags := processor.FlowHandler(&flow)
	//TODO expectedTags 一条一条详细列出来
	expectedTags := []string{"127.0.0.1 8192", "192.168.0.1 192.168.0.2 1 5 3 5 1296", "192.168.0.1 192.168.0.2 3 5 127.0.0.1 9232", "192.168.0.1 192.168.0.2 6 9 9 11:22:33:44:55:66 11:22:33:33:55:66 560", "192.168.0.1 192.168.0.2 6 9 9 528", "192.168.0.2 192.168.0.1 2 3 5 3 1296", "192.168.0.2 192.168.0.1 5 3 127.0.0.1 9232", "192.168.0.2 192.168.0.1 6 9 9 11:22:33:33:55:66 11:22:33:44:55:66 560", "192.168.0.2 192.168.0.1 6 9 9 528"}

	if len(tags) != len(expectedTags) {
		t.Error("输出文档数不正确")
	}

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
