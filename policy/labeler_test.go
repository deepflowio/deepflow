package policy

import (
	"testing"

	"gitlab.x.lan/yunshan/droplet-libs/datatype"
)

func TestGetPlatformData(t *testing.T) {

	ply := NewPolicyTable(ACTION_PACKET_STAT)

	srcIp := datatype.NewIPFromString("192.168.2.12")
	dstIp := datatype.NewIPFromString("192.168.0.11")
	key := &LookupKey{
		SrcIp:       srcIp.Int(),
		SrcMac:      0x80027a42bfc,
		DstMac:      0x80027a42bfa,
		DstIp:       dstIp.Int(),
		RxInterface: 196610,
	}
	ip := datatype.NewIPFromString("192.168.0.11")
	ipInfo := IpNet{
		Ip:       ip.Int(),
		SubnetId: 121,
		Netmask:  24,
	}

	ip1 := datatype.NewIPFromString("192.168.0.12")
	ipInfo1 := IpNet{
		Ip:       ip1.Int(),
		SubnetId: 122,
		Netmask:  25,
	}

	mac := datatype.NewMACAddrFromString("08:00:27:a4:2b:fc")
	launchServer := datatype.NewIPFromString("10.10.10.10")
	vifData := PlatformData{
		EpcId:      11,
		DeviceType: 2,
		DeviceId:   3,
		IfType:     3,
		IfIndex:    5,
		Mac:        mac.Int(),
		HostIp:     launchServer.Int(),
	}

	vifData.Ips = append(vifData.Ips, &ipInfo)
	vifData.Ips = append(vifData.Ips, &ipInfo1)

	ip2 := datatype.NewIPFromString("192.168.2.0")
	ipinfo2 := IpNet{
		Ip:       ip2.Int(),
		SubnetId: 125,
		Netmask:  24,
	}

	ip3 := datatype.NewIPFromString("192.168.2.12")

	ipInfo3 := IpNet{
		Ip:       ip3.Int(),
		SubnetId: 126,
		Netmask:  32,
	}

	mac1 := datatype.NewMACAddrFromString("08:00:27:a4:2b:fa")
	launchserver1 := datatype.NewIPFromString("10.10.10.10")

	vifData1 := PlatformData{
		EpcId:      0,
		DeviceType: 1,
		DeviceId:   100,
		IfType:     3,
		IfIndex:    5,
		Mac:        mac1.Int(),
		HostIp:     launchserver1.Int(),
	}

	vifData1.Ips = append(vifData1.Ips, &ipinfo2)
	vifData1.Ips = append(vifData1.Ips, &ipInfo3)

	var datas []*PlatformData
	datas = append(datas, &vifData)
	datas = append(datas, &vifData1)
	ply.UpdateInterfaceData(datas)
	result, _ := ply.LookupAllByKey(key)
	if result != nil {
		t.Log(result.SrcInfo, "\n")
		t.Log(result.DstInfo, "\n")
	}
	/*
		vifData1 := labeler.VifData{
			EpcId:      1,
			DeviceType: 2,
			DeviceId:   3,
			IfType:     12,
			IfIndex:    4,
			Mac:        0x123132,
			HostIp:     123131,
		}

		var data1s []*labeler.VifData

		data1s = append(data1s, &vifData1)

		labler.UpdatePlatformData(data1s)
		result = labler.GetPlatformData(key)
		fmt.Print(result)
		key.SrcMac = 0x123132
		result = labler.GetPlatformData(key)
		fmt.Print(result)
	*/
}
