/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package grpc

import (
	"encoding/binary"
	"net"
	"reflect"
	"sort"
	"testing"

	"github.com/google/gopacket/layers"

	"github.com/deepflowio/deepflow/server/libs/logger"
	"github.com/deepflowio/deepflow/server/libs/policy"
	api "github.com/deepflowio/deepflow/server/libs/reciter-api"
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
	labeler := NewGroupLabeler(nil, rawGroupMaps, 1<<10, "")
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
	result = labeler.QueryService(1, binary.BigEndian.Uint32([]byte{172, 16, 2, 233}), 0, layers.IPProtocolTCP, 150)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 2 || result[0] != 1 || result[1] != 3 {
		t.Error("group查询不正确", result)
	}
	result = labeler.QueryService(1, binary.BigEndian.Uint32([]byte{172, 16, 2, 233}), 0, layers.IPProtocolTCP, 250)
	if len(result) != 1 || result[0] != 1 {
		t.Error("group查询不正确", result)
	}
	result = labeler.QueryService(1, binary.BigEndian.Uint32([]byte{172, 21, 2, 233}), 0, layers.IPProtocolIPv6HopByHop, 444)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 2 || result[0] != 2 || result[1] != 4 {
		t.Error("group查询不正确", result)
	}
	result = labeler.QueryService(1, binary.BigEndian.Uint32([]byte{172, 21, 2, 233}), 1234, layers.IPProtocolIPv6HopByHop, 444)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 3 || result[0] != 2 || result[1] != 4 || result[2] != 5 {
		t.Error("group查询不正确", result)
	}
}

func TestDuplicateIDGroups(t *testing.T) {
	rawGroupMaps := []api.GroupIDMap{
		{L3EpcID: 1, GroupID: 233, CIDRs: []string{"172.16.0.0/16", "172.20.0.0/16"}, Protocol: policy.PROTO_ALL, ServerPorts: "123,321"},
		{L3EpcID: 1, GroupID: 233, CIDRs: []string{"172.21.0.0/16"}, Protocol: policy.PROTO_ALL},
		{L3EpcID: 51, GroupID: 233, CIDRs: []string{"172.20.0.0/16"}, Protocol: uint16(layers.IPProtocolTCP), ServerPorts: "22"},
		{L3EpcID: 1, GroupID: 233, CIDRs: []string{"172.21.0.0/16"}, Protocol: policy.PROTO_ALL, ServerPorts: "444,25-123"},
	}
	labeler := NewGroupLabeler(nil, rawGroupMaps, 1<<10, "")
	var result []uint16
	result = labeler.QueryService(1, binary.BigEndian.Uint32([]byte{172, 16, 2, 233}), 0, layers.IPProtocolTCP, 123)
	if len(result) != 1 || result[0] != 233 {
		t.Error("group查询不正确")
	}
	result = labeler.QueryService(51, binary.BigEndian.Uint32([]byte{172, 20, 2, 233}), 0, layers.IPProtocolTCP, 22)
	if len(result) != 1 || result[0] != 233 {
		t.Error("group查询不正确")
	}
	result = labeler.QueryService(1, binary.BigEndian.Uint32([]byte{172, 16, 2, 233}), 0, layers.IPProtocolTCP, 22)
	if len(result) != 0 {
		t.Error("group查询不正确")
	}
	result = labeler.QueryService(51, binary.BigEndian.Uint32([]byte{172, 20, 2, 233}), 0, layers.IPProtocolTCP, 321)
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
	labeler := NewGroupLabeler(nil, rawGroupMaps, 1<<10, "")
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
	result = labeler.QueryServiceIPv6(1, ip[:], 0, layers.IPProtocolTCP, 150)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 2 || result[0] != 1 || result[1] != 3 {
		t.Error("group查询不正确")
	}
	result = labeler.QueryServiceIPv6(1, ip[:], 0, layers.IPProtocolTCP, 250)
	if len(result) != 1 || result[0] != 1 {
		t.Error("group查询不正确")
	}
	binary.BigEndian.PutUint64(ip[:], 0xdeafbeeffeedbabe)
	result = labeler.QueryServiceIPv6(1, ip[:], 0, layers.IPProtocolIPv6HopByHop, 444)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) != 2 || result[0] != 2 || result[1] != 4 {
		t.Error("group查询不正确")
	}
	result = labeler.QueryServiceIPv6(1, ip[:], 1234, layers.IPProtocolIPv6HopByHop, 444)
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
	labeler := NewGroupLabeler(nil, rawGroupMaps, 1<<10, "")
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
	labeler := NewGroupLabeler(nil, rawGroupMaps, 1<<10, "")
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

func IPv6RangeGroups(t *testing.T) {
	rawGroupMaps := []api.GroupIDMap{
		{L3EpcID: 1, GroupID: 1, CIDRs: []string{"babe:face::/32"}},
		{L3EpcID: 1, GroupID: 2, IPRanges: []string{"babe:face:beef:bea0::-babe:face:beef:beaf:ffff:ffff:ffff:ffff"}},
		{L3EpcID: 1, GroupID: 3, CIDRs: []string{"babe:face:beef:cafe::/64", "babe:face:beef:bead::/80"}},
		{L3EpcID: 1, GroupID: 4, IPRanges: []string{"babe:face:beef:bea0::-babe:face:beef:bead:233::dead:beae"}},
	}
	labeler := NewGroupLabeler(nil, rawGroupMaps, 1<<10, "")
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
	labeler := NewGroupLabeler(nil, rawGroupMaps, 1<<10, "")
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
	labeler := NewGroupLabeler(nil, rawGroupMaps, 1<<10, "")
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
	filter := newPortFilter(nil, groupIDMap, 1000, "")
	for _, tc := range testcases {
		if filter.check(tc.groupIDIndex, tc.protocol, tc.serverPort) != tc.match {
			t.Errorf("%v查询结果不正确", tc)
		}
	}
}

func BenchmarkService10000(b *testing.B) {
	services := make([]api.GroupIDMap, 10000)
	for i, _ := range services {
		svc := &services[i]
		svc.GroupID = uint16(i)
		svc.L3EpcID = int32(i % 10)
		svc.CIDRs = []string{"172.16.0.0/16", "172.20.0.0/16", "10.0.0.0/8"}
		svc.IPRanges = []string{"10.0.0.0-11.0.0.0", "192.168.1.1-192.168.10.1"}
		svc.Protocol = policy.PROTO_ALL
		svc.ServerPorts = "22,12000-13000,30000-40000"
		svc.ServiceID = uint32(i)
	}
	l, _ := logger.GetPrefixLogger("test", "")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t := NewGroupLabeler(l, services, 1<<20, "test")
		t.portFilter.fastMap.Close()
	}
}
