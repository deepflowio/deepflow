package policy

import (
	"net"
	"reflect"
	"testing"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

var groups []*IpGroupData = []*IpGroupData{
	&IpGroupData{Id: 1, EpcId: 1, Type: NAMED, Ips: []string{"1234:1234:1234::1/24"}},
	&IpGroupData{Id: 2, EpcId: 1, Type: NAMED, Ips: []string{"1234:1134:1234::2/16"}},
	&IpGroupData{Id: 3, EpcId: 2, Type: NAMED, Ips: []string{"1234:1434:1234::2/16"}},
	&IpGroupData{Id: 4, EpcId: 2, Type: NAMED, Ips: []string{"1234:1434:1234::2/8"}},
	&IpGroupData{Id: 5, EpcId: 3, Type: NAMED, Ips: []string{"1234:1234:1234::2/128"}},
	&IpGroupData{Id: 6, EpcId: 0, Type: NAMED, Ips: []string{"1234:1234:1234::2/128"}}, // EpcId为0，匹配所有EpcId
}

func generateIpResourceGroup() *IpResourceGroup {
	finder := NewIpResourceGroup()
	finder.Update(groups)
	return finder
}

func getGroups(finder *IpResourceGroup, ip net.IP, epc int32) []uint32 {
	endpoint := &EndpointInfo{L3EpcId: epc}
	if ip.To4() == nil {
		return finder.GetGroupIdsByIpv6(ip, endpoint)
	} else {
		return finder.GetGroupIds(IpToUint32(ip), endpoint)
	}
}

func TestIp6Group(t *testing.T) {
	finder := generateIpResourceGroup()
	result := getGroups(finder, net.ParseIP("1234:1222:1234::3"), 1)
	expect := []uint32{1, 2}
	if !reflect.DeepEqual(result, expect) {
		t.Error("TestIp6Group failed!")
		t.Log("Result:", result, "\n")
		t.Log("Expect:", expect, "\n")
	}
	result = getGroups(finder, net.ParseIP("1234:1222:1234::3"), 2)
	expect = []uint32{3, 4}
	if !reflect.DeepEqual(result, expect) {
		t.Error("TestIp6Group failed!")
		t.Log("Result:", result, "\n")
		t.Log("Expect:", expect, "\n")
	}
	result = getGroups(finder, net.ParseIP("1234:1234:1234::2"), 3)
	expect = []uint32{5, 6}
	if !reflect.DeepEqual(result, expect) {
		t.Error("TestIp6Group failed!")
		t.Log("Result:", result, "\n")
		t.Log("Expect:", expect, "\n")
	}
	result = getGroups(finder, net.ParseIP("1234:1234:1234::1"), 3)
	if len(result) != 0 {
		t.Error("TestIp6Group failed!")
		t.Log("Result:", result, "\n")
		t.Log("Expect:", expect, "\n")
	}
}
