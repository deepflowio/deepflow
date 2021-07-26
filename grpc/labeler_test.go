package grpc

import (
	"encoding/binary"
	"net"
	"reflect"
	"sort"
	"testing"

	"github.com/google/gopacket/layers"

	"gitlab.yunshan.net/yunshan/droplet-libs/policy"
	api "gitlab.yunshan.net/yunshan/droplet-libs/reciter-api"
)

func TestDedup(t *testing.T) {
	testcases := []struct {
		orig     []uint16
		expected []uint16
	}{
		{[]uint16{1, 2, 2, 3, 3, 4, 4, 4, 5, 1, 3, 2, 5, 6}, []uint16{1, 2, 3, 4, 5, 6}},
		{[]uint16{}, []uint16{}},
		{[]uint16{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3}, []uint16{3}},
		{[]uint16{9, 8, 8, 5, 9}, []uint16{5, 8, 9}},
		{[]uint16{9}, []uint16{9}},
	}
	for _, tc := range testcases {
		if result := dedup(tc.orig); !reflect.DeepEqual(tc.expected, result) {
			t.Errorf("%v去重结果不正确: %v", tc, result)
		}
	}
}

func TestSimpleGroups(t *testing.T) {
	rawGroupMaps := []api.GroupIDMap{
		{L3EpcID: 1, GroupID: 1, CIDRs: []string{"172.16.0.0/16", "172.20.0.0/16"}, Protocol: policy.PROTO_ALL},
		{L3EpcID: 1, GroupID: 2, CIDRs: []string{"172.21.0.0/16"}, Protocol: policy.PROTO_ALL},
		{L3EpcID: 1, GroupID: 3, CIDRs: []string{"172.16.0.0/16", "172.20.0.0/16"}, Protocol: uint16(layers.IPProtocolTCP), ServerPorts: "22,100-200"},
		{L3EpcID: 1, GroupID: 4, CIDRs: []string{"172.21.0.0/16"}, Protocol: policy.PROTO_ALL, ServerPorts: "444,25-123"},
		{GroupID: 5, PodGroupID: 1234, Protocol: policy.PROTO_ALL, ServerPorts: "444,25-123"},
	}
	labeler := NewGroupLabeler(nil, rawGroupMaps)
	var result []uint16
	result = labeler.Query(1, binary.BigEndian.Uint32([]byte{172, 16, 2, 233}), 0)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 2 || result[0] != 1 || result[1] != 3 {
		t.Error("group查询不正确")
	}
	result = labeler.Query(1, binary.BigEndian.Uint32([]byte{172, 21, 2, 233}), 0)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 2 || result[0] != 2 || result[1] != 4 {
		t.Error("group查询不正确")
	}
	result = labeler.Query(1, binary.BigEndian.Uint32([]byte{192, 21, 2, 233}), 0)
	if len(result) != 0 {
		t.Error("group查询不正确")
	}
	result = labeler.QueryServer(1, binary.BigEndian.Uint32([]byte{172, 16, 2, 233}), 0, layers.IPProtocolTCP, 150)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 2 || result[0] != 1 || result[1] != 3 {
		t.Error("group查询不正确")
	}
	result = labeler.QueryServer(1, binary.BigEndian.Uint32([]byte{172, 16, 2, 233}), 0, layers.IPProtocolTCP, 250)
	if len(result) != 1 || result[0] != 1 {
		t.Error("group查询不正确")
	}
	result = labeler.QueryServer(1, binary.BigEndian.Uint32([]byte{172, 21, 2, 233}), 0, layers.IPProtocolIPv6HopByHop, 444)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 2 || result[0] != 2 || result[1] != 4 {
		t.Error("group查询不正确")
	}
	result = labeler.QueryServer(1, binary.BigEndian.Uint32([]byte{172, 21, 2, 233}), 1234, layers.IPProtocolIPv6HopByHop, 444)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 3 || result[0] != 2 || result[1] != 4 || result[2] != 5 {
		t.Error("group查询不正确")
	}
}

func TestDuplicateIDGroups(t *testing.T) {
	rawGroupMaps := []api.GroupIDMap{
		{L3EpcID: 1, GroupID: 233, CIDRs: []string{"172.16.0.0/16", "172.20.0.0/16"}, Protocol: policy.PROTO_ALL, ServerPorts: "123,321"},
		{L3EpcID: 1, GroupID: 233, CIDRs: []string{"172.21.0.0/16"}, Protocol: policy.PROTO_ALL},
		{L3EpcID: 51, GroupID: 233, CIDRs: []string{"172.20.0.0/16"}, Protocol: uint16(layers.IPProtocolTCP), ServerPorts: "22"},
		{L3EpcID: 1, GroupID: 233, CIDRs: []string{"172.21.0.0/16"}, Protocol: policy.PROTO_ALL, ServerPorts: "444,25-123"},
	}
	labeler := NewGroupLabeler(nil, rawGroupMaps)
	var result []uint16
	result = labeler.QueryServer(1, binary.BigEndian.Uint32([]byte{172, 16, 2, 233}), 0, layers.IPProtocolTCP, 123)
	if len(result) != 1 || result[0] != 233 {
		t.Error("group查询不正确")
	}
	result = labeler.QueryServer(51, binary.BigEndian.Uint32([]byte{172, 20, 2, 233}), 0, layers.IPProtocolTCP, 22)
	if len(result) != 1 || result[0] != 233 {
		t.Error("group查询不正确")
	}
	result = labeler.QueryServer(1, binary.BigEndian.Uint32([]byte{172, 16, 2, 233}), 0, layers.IPProtocolTCP, 22)
	if len(result) != 0 {
		t.Error("group查询不正确")
	}
	result = labeler.QueryServer(51, binary.BigEndian.Uint32([]byte{172, 20, 2, 233}), 0, layers.IPProtocolTCP, 321)
	if len(result) != 0 {
		t.Error("group查询不正确")
	}
}

func TestSimpleIPv6Groups(t *testing.T) {
	rawGroupMaps := []api.GroupIDMap{
		{L3EpcID: 1, GroupID: 1, CIDRs: []string{"babe:face:beef:cafe::/64", "babe:face:beef:bead::/64"}, Protocol: policy.PROTO_ALL},
		{L3EpcID: 1, GroupID: 2, CIDRs: []string{"deaf:beef:feed:babe::/64"}, Protocol: policy.PROTO_ALL},
		{L3EpcID: 1, GroupID: 3, CIDRs: []string{"babe:face:beef:cafe::/64", "babe:face:beef:bead::/64"}, Protocol: uint16(layers.IPProtocolTCP), ServerPorts: "22,100-200"},
		{L3EpcID: 1, GroupID: 4, CIDRs: []string{"deaf:beef:feed:babe::/64"}, Protocol: policy.PROTO_ALL, ServerPorts: "444,25-123"},
		{GroupID: 5, PodGroupID: 1234, Protocol: policy.PROTO_ALL, ServerPorts: "444,25-123"},
	}
	labeler := NewGroupLabeler(nil, rawGroupMaps)
	var ip [net.IPv6len]byte
	ip[net.IPv6len-1] = 1
	var result []uint16

	binary.BigEndian.PutUint64(ip[:], 0xbabefacebeefcafe)
	result = labeler.QueryIPv6(1, ip[:], 0)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 2 || result[0] != 1 || result[1] != 3 {
		t.Error("group查询不正确")
	}
	binary.BigEndian.PutUint64(ip[:], 0xdeafbeeffeedbabe)
	result = labeler.QueryIPv6(1, ip[:], 0)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 2 || result[0] != 2 || result[1] != 4 {
		t.Error("group查询不正确")
	}
	binary.BigEndian.PutUint64(ip[:], 0xdeadbeefbeadbabe)
	result = labeler.QueryIPv6(1, ip[:], 0)
	if len(result) != 0 {
		t.Error("group查询不正确")
	}
	binary.BigEndian.PutUint64(ip[:], 0xbabefacebeefcafe)
	result = labeler.QueryServerIPv6(1, ip[:], 0, layers.IPProtocolTCP, 150)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 2 || result[0] != 1 || result[1] != 3 {
		t.Error("group查询不正确")
	}
	result = labeler.QueryServerIPv6(1, ip[:], 0, layers.IPProtocolTCP, 250)
	if len(result) != 1 || result[0] != 1 {
		t.Error("group查询不正确")
	}
	binary.BigEndian.PutUint64(ip[:], 0xdeafbeeffeedbabe)
	result = labeler.QueryServerIPv6(1, ip[:], 0, layers.IPProtocolIPv6HopByHop, 444)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 2 || result[0] != 2 || result[1] != 4 {
		t.Error("group查询不正确")
	}
	result = labeler.QueryServerIPv6(1, ip[:], 1234, layers.IPProtocolIPv6HopByHop, 444)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 3 || result[0] != 2 || result[1] != 4 || result[2] != 5 {
		t.Error("group查询不正确")
	}
}

func TestOverlappingGroups(t *testing.T) {
	rawGroupMaps := []api.GroupIDMap{
		{L3EpcID: 1, GroupID: 1, CIDRs: []string{"10.0.0.0/8"}},
		{L3EpcID: 1, GroupID: 2, CIDRs: []string{"10.128.0.0/9"}},
		{L3EpcID: 1, GroupID: 3, CIDRs: []string{"10.16.0.0/16", "10.130.0.0/24"}},
	}
	labeler := NewGroupLabeler(nil, rawGroupMaps)
	var result []uint16
	result = labeler.Query(1, binary.BigEndian.Uint32([]byte{10, 16, 2, 233}), 0)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 2 || result[0] != 1 || result[1] != 3 {
		t.Error("group查询不正确")
	}
	result = labeler.Query(1, binary.BigEndian.Uint32([]byte{10, 130, 3, 233}), 0)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 2 || result[0] != 1 || result[1] != 2 {
		t.Error("group查询不正确")
	}
	result = labeler.Query(1, binary.BigEndian.Uint32([]byte{10, 130, 0, 233}), 0)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 3 || result[0] != 1 || result[1] != 2 || result[2] != 3 {
		t.Error("group查询不正确")
	}
}

func TestIPRangeGroups(t *testing.T) {
	rawGroupMaps := []api.GroupIDMap{
		{L3EpcID: 1, GroupID: 1, CIDRs: []string{"10.0.0.0/8"}},
		{L3EpcID: 1, GroupID: 2, IPRanges: []string{"10.128.0.0-10.255.255.255"}},
		{L3EpcID: 1, GroupID: 3, CIDRs: []string{"10.16.0.0/16", "10.130.0.0/24"}},
		{L3EpcID: 1, GroupID: 4, IPRanges: []string{"10.128.0.0-10.130.3.232"}},
	}
	labeler := NewGroupLabeler(nil, rawGroupMaps)
	var result []uint16
	result = labeler.Query(1, binary.BigEndian.Uint32([]byte{10, 16, 2, 233}), 0)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 2 || result[0] != 1 || result[1] != 3 {
		t.Error("group查询不正确")
	}
	result = labeler.Query(1, binary.BigEndian.Uint32([]byte{10, 130, 3, 233}), 0)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 2 || result[0] != 1 || result[1] != 2 {
		t.Error("group查询不正确")
	}
	result = labeler.Query(1, binary.BigEndian.Uint32([]byte{10, 130, 0, 233}), 0)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 4 || result[0] != 1 || result[1] != 2 || result[2] != 3 || result[3] != 4 {
		t.Error("group查询不正确")
	}
}

func TestIPv6RangeGroups(t *testing.T) {
	rawGroupMaps := []api.GroupIDMap{
		{L3EpcID: 1, GroupID: 1, CIDRs: []string{"babe:face::/32"}},
		{L3EpcID: 1, GroupID: 2, IPRanges: []string{"babe:face:beef:bea0::-babe:face:beef:beaf:ffff:ffff:ffff:ffff"}},
		{L3EpcID: 1, GroupID: 3, CIDRs: []string{"babe:face:beef:cafe::/64", "babe:face:beef:bead::/80"}},
		{L3EpcID: 1, GroupID: 4, IPRanges: []string{"babe:face:beef:bea0::-babe:face:beef:bead:233::dead:beae"}},
	}
	labeler := NewGroupLabeler(nil, rawGroupMaps)
	var ip [net.IPv6len]byte
	ip[net.IPv6len-1] = 1
	var result []uint16
	binary.BigEndian.PutUint64(ip[:], 0xbabefacebeefcafe)
	result = labeler.QueryIPv6(1, ip[:], 0)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 2 || result[0] != 1 || result[1] != 3 {
		t.Error("group查询不正确")
	}
	binary.BigEndian.PutUint64(ip[:], 0xbabefacebeefbead)
	binary.BigEndian.PutUint64(ip[net.IPv6len/2:], 0x2330000deadbeef)
	result = labeler.QueryIPv6(1, ip[:], 0)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 2 || result[0] != 1 || result[1] != 2 {
		t.Error("group查询不正确")
	}
	binary.BigEndian.PutUint64(ip[:], 0xbabefacebeefbead)
	binary.BigEndian.PutUint64(ip[net.IPv6len/2:], 0xdeadbeef)
	result = labeler.QueryIPv6(1, ip[:], 0)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 4 || result[0] != 1 || result[1] != 2 || result[2] != 3 || result[3] != 4 {
		t.Error("group查询不正确")
	}
}

func TestMixedIPGroups(t *testing.T) {
	rawGroupMaps := []api.GroupIDMap{
		{L3EpcID: 1, GroupID: 1, CIDRs: []string{"10.0.0.0/8", "babe:face::/32"}},
		{L3EpcID: 1, GroupID: 2, IPRanges: []string{"10.128.0.0-10.255.255.255", "babe:face:beef:bea0::-babe:face:beef:beaf:ffff:ffff:ffff:ffff"}},
		{L3EpcID: 1, GroupID: 3, CIDRs: []string{"10.16.0.0/16", "10.130.0.0/24", "babe:face:beef:cafe::/64", "babe:face:beef:bead::/80"}},
		{L3EpcID: 1, GroupID: 4, IPRanges: []string{"10.128.0.0-10.130.3.232", "babe:face:beef:bea0::-babe:face:beef:bead:233::dead:beae"}},
	}
	labeler := NewGroupLabeler(nil, rawGroupMaps)
	var ip [net.IPv6len]byte
	ip[net.IPv6len-1] = 1
	var result []uint16

	result = labeler.Query(1, binary.BigEndian.Uint32([]byte{10, 16, 2, 233}), 0)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 2 || result[0] != 1 || result[1] != 3 {
		t.Error("group查询不正确")
	}
	result = labeler.Query(1, binary.BigEndian.Uint32([]byte{10, 130, 3, 233}), 0)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 2 || result[0] != 1 || result[1] != 2 {
		t.Error("group查询不正确")
	}
	result = labeler.Query(1, binary.BigEndian.Uint32([]byte{10, 130, 0, 233}), 0)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 4 || result[0] != 1 || result[1] != 2 || result[2] != 3 || result[3] != 4 {
		t.Error("group查询不正确")
	}

	binary.BigEndian.PutUint64(ip[:], 0xbabefacebeefcafe)
	result = labeler.QueryIPv6(1, ip[:], 0)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 2 || result[0] != 1 || result[1] != 3 {
		t.Error("group查询不正确")
	}
	binary.BigEndian.PutUint64(ip[:], 0xbabefacebeefbead)
	binary.BigEndian.PutUint64(ip[net.IPv6len/2:], 0x2330000deadbeef)
	result = labeler.QueryIPv6(1, ip[:], 0)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 2 || result[0] != 1 || result[1] != 2 {
		t.Error("group查询不正确")
	}
	binary.BigEndian.PutUint64(ip[:], 0xbabefacebeefbead)
	binary.BigEndian.PutUint64(ip[net.IPv6len/2:], 0xdeadbeef)
	result = labeler.QueryIPv6(1, ip[:], 0)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 4 || result[0] != 1 || result[1] != 2 || result[2] != 3 || result[3] != 4 {
		t.Error("group查询不正确")
	}
}

func TestAnyRuleGroups(t *testing.T) {
	rawGroupMaps := []api.GroupIDMap{
		{L3EpcID: 2, GroupID: 1, IPRanges: []string{"0.0.0.0-255.255.255.255"}},
		{L3EpcID: 0, GroupID: 2, IPRanges: []string{"10.128.0.0-10.255.255.255"}},
	}
	labeler := NewGroupLabeler(nil, rawGroupMaps)
	var result []uint16
	result = labeler.Query(2, binary.BigEndian.Uint32([]byte{10, 16, 2, 233}), 0)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 1 || result[0] != 1 {
		t.Error("group查询不正确")
	}
	result = labeler.Query(3, binary.BigEndian.Uint32([]byte{10, 130, 3, 233}), 0)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 1 || result[0] != 2 {
		t.Error("group查询不正确")
	}
	result = labeler.Query(2, binary.BigEndian.Uint32([]byte{10, 130, 0, 233}), 0)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 2 || result[0] != 1 || result[1] != 2 {
		t.Error("group查询不正确")
	}
	result = labeler.Query(-1, binary.BigEndian.Uint32([]byte{10, 130, 0, 233}), 0)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 1 || result[0] != 2 {
		t.Error("group查询不正确")
	}
}

func TestPortFilter(t *testing.T) {
	groupIDMap := []api.GroupIDMap{
		{GroupID: 1, Protocol: uint16(layers.IPProtocolTCP), ServerPorts: "22,100-200"},
		{GroupID: 2, Protocol: uint16(layers.IPProtocolIPv6HopByHop), ServerPorts: "150-300"},
		{GroupID: 3, Protocol: policy.PROTO_ALL, ServerPorts: ""},
		{GroupID: 4, Protocol: policy.PROTO_ALL, ServerPorts: "0"},
	}
	testcases := []struct {
		groupIDIndex int16
		protocol     layers.IPProtocol
		serverPort   uint16
		match        bool
	}{
		{0, layers.IPProtocolTCP, 175, true},
		{0, layers.IPProtocolTCP, 22, true},
		{0, layers.IPProtocolTCP, 300, false},
		{1, layers.IPProtocolIPv6HopByHop, 200, true},
		{1, layers.IPProtocolTCP, 200, false},
		{1, layers.IPProtocolIPv6HopByHop, 350, false},
		{2, layers.IPProtocolUDP, 350, true},
		{2, layers.IPProtocolIPv6HopByHop, 350, true},
		{3, layers.IPProtocolUDP, 0, true},
		{3, layers.IPProtocolIPv6HopByHop, 350, false},
	}
	filter := newPortFilter(nil, groupIDMap)
	for _, tc := range testcases {
		if filter.check(tc.groupIDIndex, tc.protocol, tc.serverPort) != tc.match {
			t.Errorf("%v查询结果不正确", tc)
		}
	}
}
