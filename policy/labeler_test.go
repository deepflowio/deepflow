package policy

import (
	"testing"

	"gitlab.x.lan/yunshan/droplet-libs/message"
)

func TestGetPlatformData(t *testing.T) {

	ply := NewPolicyTable(ACTION_PACKET_STAT)

	srcip := message.NewIPFromString("192.168.2.12")
	dstip := message.NewIPFromString("192.168.0.11")
	key := &LookupKey{
		SrcIp:       srcip.Int(),
		SrcMac:      0x80027a42bfc,
		DstMac:      0x80027a42bfa,
		DstIp:       dstip.Int(),
		RxInterface: 196610,
	}
	ip := message.NewIPFromString("192.168.0.11")
	ipinfo := IpNet{
		Ip:       ip.Int(),
		SubnetId: 121,
		Netmask:  24,
	}

	ip1 := message.NewIPFromString("192.168.0.12")
	ipinfo1 := IpNet{
		Ip:       ip1.Int(),
		SubnetId: 122,
		Netmask:  25,
	}

	mac := message.NewMACAddrFromString("08:00:27:a4:2b:fc")
	launchserver := message.NewIPFromString("10.10.10.10")
	vifdata := PlatformData{
		EpcId:      11,
		DeviceType: 2,
		DeviceId:   3,
		IfType:     3,
		IfIndex:    5,
		Mac:        mac.Int(),
		HostIp:     launchserver.Int(),
	}

	vifdata.Ips = append(vifdata.Ips, &ipinfo)
	vifdata.Ips = append(vifdata.Ips, &ipinfo1)

	ip2 := message.NewIPFromString("192.168.2.0")
	ipinfo2 := IpNet{
		Ip:       ip2.Int(),
		SubnetId: 125,
		Netmask:  24,
	}

	ip3 := message.NewIPFromString("192.168.2.12")

	ipinfo3 := IpNet{
		Ip:       ip3.Int(),
		SubnetId: 126,
		Netmask:  32,
	}

	mac1 := message.NewMACAddrFromString("08:00:27:a4:2b:fa")
	launchserver1 := message.NewIPFromString("10.10.10.10")

	vifdata1 := PlatformData{
		EpcId:      0,
		DeviceType: 1,
		DeviceId:   100,
		IfType:     3,
		IfIndex:    5,
		Mac:        mac1.Int(),
		HostIp:     launchserver1.Int(),
	}

	vifdata1.Ips = append(vifdata1.Ips, &ipinfo2)
	vifdata1.Ips = append(vifdata1.Ips, &ipinfo3)

	var datas []*PlatformData
	datas = append(datas, &vifdata)
	datas = append(datas, &vifdata1)
	ply.UpdateInterfaceData(datas)
	result, _ := ply.LookupAllByKey(key)
	if result != nil {
		t.Log(result.SrcInfo, "\n")
		t.Log(result.DstInfo, "\n")
	}
	/*
		vifdata1 := labeler.VifData{
			EpcId:      1,
			DeviceType: 2,
			DeviceId:   3,
			IfType:     12,
			IfIndex:    4,
			Mac:        0x123132,
			HostIp:     123131,
		}

		var data1s []*labeler.VifData

		data1s = append(data1s, &vifdata1)

		labler.UpdatePlatformData(data1s)
		result = labler.GetPlatformData(key)
		fmt.Print(result)
		key.SrcMac = 0x123132
		result = labler.GetPlatformData(key)
		fmt.Print(result)
	*/
}
