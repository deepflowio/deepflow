package policy

import (
	"net"
	"reflect"
	"testing"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

var groups []*IpGroupData = []*IpGroupData{
	&IpGroupData{Id: 1, EpcId: 1, Type: IP_GROUP, Ips: []string{"1234:1234:1234::1/24"}},
	&IpGroupData{Id: 2, EpcId: 1, Type: IP_GROUP, Ips: []string{"1234:1134:1234::2/16"}},
	&IpGroupData{Id: 3, EpcId: 2, Type: VM_GROUP, Ips: []string{"1234:1434:1234::2/16"}},
	&IpGroupData{Id: 4, EpcId: 2, Type: VM_GROUP, Ips: []string{"1234:1434:1234::2/8"}},
	&IpGroupData{Id: 5, EpcId: 3, Type: VM_GROUP, Ips: []string{"1234:1234:1234::2/128"}},
	&IpGroupData{Id: 6, EpcId: 0, Type: VM_GROUP, Ips: []string{"1234:1234:1234::2/128"}},
}

func generateIpResourceGroup() *IpResourceGroup {
	finder := NewIpResourceGroup()
	finder.Update(groups)
	return finder
}

func getGroups(finder *IpResourceGroup, ip net.IP, epc int32) []uint32 {
	endpoint := &EndpointInfo{L3EpcId: epc}
	finder.Populate(ip, endpoint)
	return endpoint.GroupIds
}

func TestIp6Group(t *testing.T) {
	finder := generateIpResourceGroup()
	result := getGroups(finder, net.ParseIP("1234:1222:1234::3"), 1)
	expect := []uint32{1 + IP_GROUP_ID_FLAG, 2 + IP_GROUP_ID_FLAG}
	if !reflect.DeepEqual(result, expect) {
		t.Error("TestIp6Group failed!")
		t.Log("Result:", result, "\n")
		t.Log("Expect:", expect, "\n")
	}
	result = getGroups(finder, net.ParseIP("1234:1222:1234::3"), 2)
	expect = []uint32{3 + IP_GROUP_ID_FLAG, 4 + IP_GROUP_ID_FLAG}
	if !reflect.DeepEqual(result, expect) {
		t.Error("TestIp6Group failed!")
		t.Log("Result:", result, "\n")
		t.Log("Expect:", expect, "\n")
	}
	result = getGroups(finder, net.ParseIP("1234:1234:1234::2"), 3)
	expect = []uint32{5 + IP_GROUP_ID_FLAG, 6 + IP_GROUP_ID_FLAG}
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
