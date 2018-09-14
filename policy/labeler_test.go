package policy

import (
	"testing"
	"time"

	. "github.com/google/gopacket/layers"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

func TestGetPlatformData(t *testing.T) {

	policy := NewPolicyTable(ACTION_PACKET_STAT, 1)

	srcIp := NewIPFromString("192.168.2.12")
	dstIp := NewIPFromString("192.168.0.11")
	key := &LookupKey{
		SrcIp:  srcIp.Int(),
		SrcMac: 0x80027a42bfc,
		DstMac: 0x80027a42bfa,
		DstIp:  dstIp.Int(),
		Tap:    TAP_TOR,
	}
	ip := NewIPFromString("192.168.0.11")
	ipInfo := IpNet{
		Ip:       ip.Int(),
		SubnetId: 121,
		Netmask:  24,
	}

	ip1 := NewIPFromString("192.168.0.12")
	ipInfo1 := IpNet{
		Ip:       ip1.Int(),
		SubnetId: 122,
		Netmask:  25,
	}

	mac := NewMACAddrFromString("08:00:27:a4:2b:fc")
	launchServer := NewIPFromString("10.10.10.10")
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

	ip2 := NewIPFromString("192.168.2.0")
	ipInfo2 := IpNet{
		Ip:       ip2.Int(),
		SubnetId: 125,
		Netmask:  24,
	}

	ip3 := NewIPFromString("192.168.2.12")

	ipInfo3 := IpNet{
		Ip:       ip3.Int(),
		SubnetId: 126,
		Netmask:  32,
	}

	mac1 := NewMACAddrFromString("08:00:27:a4:2b:fa")
	launchserver1 := NewIPFromString("10.10.10.10")

	vifData1 := PlatformData{
		EpcId:      0,
		DeviceType: 1,
		DeviceId:   100,
		IfType:     3,
		IfIndex:    5,
		Mac:        mac1.Int(),
		HostIp:     launchserver1.Int(),
	}

	vifData1.Ips = append(vifData1.Ips, &ipInfo2)
	vifData1.Ips = append(vifData1.Ips, &ipInfo3)

	var datas []*PlatformData
	datas = append(datas, &vifData)
	datas = append(datas, &vifData1)
	policy.UpdateInterfaceData(datas)
	result, _ := policy.LookupAllByKey(key)
	if result != nil {
		t.Log(result.SrcInfo, "\n")
		t.Log(result.DstInfo, "\n")
	}
}

func TestGetPlatformDataAboutArp(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_STAT, 1)

	srcIp := NewIPFromString("192.168.2.12")
	dstIp := NewIPFromString("192.168.0.11")
	key := &LookupKey{
		SrcIp:   srcIp.Int(),
		SrcMac:  0x80027a42bfc,
		DstMac:  0x80027a42bfa,
		DstIp:   dstIp.Int(),
		EthType: EthernetTypeARP,
		Ttl:     64,
		Tap:     TAP_TOR,
	}
	ip := NewIPFromString("192.168.0.11")
	ipInfo := IpNet{
		Ip:       ip.Int(),
		SubnetId: 121,
		Netmask:  24,
	}

	ip1 := NewIPFromString("192.168.0.12")
	ipInfo1 := IpNet{
		Ip:       ip1.Int(),
		SubnetId: 122,
		Netmask:  25,
	}

	mac := NewMACAddrFromString("08:00:27:a4:2b:fc")
	launchServer := NewIPFromString("10.10.10.10")
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
	var datas []*PlatformData
	datas = append(datas, &vifData)
	policy.UpdateInterfaceData(datas)
	now := time.Now()
	result, _ := policy.LookupAllByKey(key)
	t.Log(time.Now().Sub(now))
	if result != nil {
		t.Log(result.SrcInfo, "\n")
		t.Log(result.DstInfo, "\n")
	}
	now = time.Now()
	result, _ = policy.LookupAllByKey(key)
	t.Log(time.Now().Sub(now))
}
