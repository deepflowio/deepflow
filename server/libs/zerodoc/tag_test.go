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

package zerodoc

import (
	"encoding/binary"
	"math"
	"net"
	"sort"
	"strings"
	"testing"

	"github.com/google/gopacket/layers"

	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/zerodoc/pb"
)

func TestHasEdgeTagField(t *testing.T) {
	c := IPPath
	if !c.HasEdgeTagField() {
		t.Error("Edge Tag处理不正确")
	}
	c = IP
	if c.HasEdgeTagField() {
		t.Error("Edge Tag处理不正确")
	}
}

func TestInt16Unmarshal(t *testing.T) {
	for i := math.MinInt16; i <= math.MaxInt16; i++ {
		v, _ := unmarshalUint16WithSpecialID(marshalUint16WithSpecialID(int16(i)))
		if int16(i) != v {
			t.Errorf("Int16序列化反序列化[%d]不正确", i)
		}
		v = unmarshalInt32WithSpecialID(marshalInt32WithSpecialID(int16(i)))
		if int16(i) != v {
			t.Errorf("Int32序列化反序列化[%d]不正确", i)
		}
	}
}

func TestNegativeID(t *testing.T) {
	f := Field{L3EpcID: datatype.EPC_FROM_DEEPFLOW}
	if f.NewTag(L3EpcID).ToKVString() != ",l3_epc_id=-1" {
		t.Error("int16值处理得不正确")
	}
	f = Field{L3EpcID: 32767}
	if f.NewTag(L3EpcID).ToKVString() != ",l3_epc_id=32767" {
		t.Error("int16值处理得不正确")
	}
}

func TestCloneTagWithIPv6Fields(t *testing.T) {
	var ip [net.IPv6len]byte
	for i := range ip {
		ip[i] = byte(i)
	}
	tagOrigin := AcquireTag()
	tagOrigin.Field = AcquireField()
	tagOrigin.IsIPv6 = 1
	tagOrigin.IP6 = ip[:net.IPv6len]
	tagCloned := CloneTag(tagOrigin)
	if !tagCloned.IP6.Equal(tagOrigin.IP6) {
		t.Error("CloneTag产生的tag和原tag字段不一致")
	}
	tagCloned.IP6[0] = 255
	if tagCloned.IP6.Equal(tagOrigin.IP6) {
		t.Error("CloneTag产生的tag和原tag共享了字段")
	}
}

type Strings []string

func (s Strings) Len() int           { return len(s) }
func (s Strings) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s Strings) Less(i, j int) bool { return s[i] < s[j] }

func parseTagkeys(b []byte) []string {
	str := string(b)
	ret := make([]string, 0)
	splits := strings.Split(str, ",")
	for _, s := range splits {
		if index := strings.Index(s, "="); index != -1 {
			ret = append(ret, s[:index])
		}
	}
	return ret
}

func TestMarshallToInfluxdb(t *testing.T) {
	b := make([]byte, 1024)
	f := Field{}
	tag := &Tag{&f, 0, ""}
	tag.GlobalThreadID = 112
	tag.Code = ^(HostIDPath | IPPath | L3DevicePath | L3EpcIDPath | RegionIDPath | SubnetIDPath | PodNodeIDPath | AZIDPath | PodGroupIDPath | PodNSIDPath | PodIDPath | PodClusterIDPath | ResourcePath)

	l := tag.MarshalTo(b)
	strs := parseTagkeys(b[:l])
	cloneStrs := make([]string, 0)
	cloneStrs = append(cloneStrs, strs...)
	sort.Sort(Strings(strs))
	if strs[0] < "_id" {
		t.Error("tag的keys在打包时, 所有key都必须小于'_id', 当前最小的key是:", strs[0])
	}

	for i, s := range cloneStrs {
		if s != strs[i] {
			t.Error("tag的keys在打包时, 没有按字典顺序排序在:", s)
		}
	}

	tag.Code = ^(HostID | IP | L3Device | L3EpcID | RegionID | SubnetID | PodNodeID | AZID | PodGroupID | PodNSID | PodID | PodClusterID | Resource)
	l = tag.MarshalTo(b)
	strs = parseTagkeys(b[:l])
	cloneStrs = cloneStrs[:0]
	cloneStrs = append(cloneStrs, strs...)
	sort.Sort(Strings(strs))
	if strs[0] < "_id" {
		t.Error("tag的keys在打包时, 所有key都必须小于'_id', 当前最小的key是:", strs[0])
	}

	for i, s := range cloneStrs {
		if s != strs[i] {
			t.Error("tag的keys在打包时, 没有按字典顺序排序在:", s)
		}
	}
}

func checkTagAndMiniTagEqual(tag *Tag, miniTag *MiniTag) bool {
	if miniTag.Code&Direction != 0 && miniTag.HasEdgeTagField() || tag.Code&TAPSide != 0 {
		if miniTag.Code&Direction == 0 || !miniTag.HasEdgeTagField() {
			return false
		}
		if tag.Code&TAPSide == 0 {
			return false
		}
		if tag.Code & ^TAPSide != miniTag.Code & ^Direction {
			return false
		}
	} else if tag.Code != miniTag.Code {
		return false
	}
	if tag.GlobalThreadID != miniTag.GlobalThreadID {
		return false
	}

	srcIP, dstIP := miniTag.IP(), miniTag.IP1()
	srcEpc, dstEpc := miniTag.L3EpcID, miniTag.L3EpcID1

	code := tag.Code

	if code&IP != 0 {
		if tag.IsIPv6 != 0 && miniTag.IsIPv6 != 0 {
			if !tag.IP6.Equal(srcIP) {
				return false
			}
		} else if tag.IsIPv6 == 0 && miniTag.IsIPv6 == 0 {
			if tag.IP != binary.BigEndian.Uint32(srcIP) {
				return false
			}
		} else {
			return false
		}
	}
	if code&L3EpcID != 0 {
		if tag.L3EpcID != srcEpc {
			return false
		}
	}

	if code&IPPath != 0 {
		if tag.IsIPv6 != 0 && miniTag.IsIPv6 != 0 {
			if !tag.IP6.Equal(srcIP) {
				return false
			}
			if !tag.IP61.Equal(dstIP) {
				return false
			}
		} else if tag.IsIPv6 == 0 && miniTag.IsIPv6 == 0 {
			if tag.IP != binary.BigEndian.Uint32(srcIP) {
				return false
			}
			if tag.IP1 != binary.BigEndian.Uint32(dstIP) {
				return false
			}
		} else {
			return false
		}
	}
	if code&L3EpcIDPath != 0 {
		if tag.L3EpcID != srcEpc {
			return false
		}
		if tag.L3EpcID1 != dstEpc {
			return false
		}
	}

	if code&ACLGID != 0 {
		if tag.ACLGID != miniTag.ACLGID {
			return false
		}
	}
	if code&Protocol != 0 {
		if tag.Protocol != miniTag.Protocol {
			return false
		}
	}
	if code&ServerPort != 0 {
		if tag.ServerPort != miniTag.ServerPort {
			return false
		}
	}
	if code&VTAPID != 0 {
		if tag.VTAPID != miniTag.VTAPID {
			return false
		}
	}
	if code&TAPType != 0 {
		if tag.TAPType != miniTag.TAPType {
			return false
		}
	}
	if code&TAPSide != 0 {
		if !(tag.TAPSide == Client && miniTag.Direction == ClientToServer || tag.TAPSide == Server && miniTag.Direction == ServerToClient) {
			return false
		}
	}

	if code&TagType != 0 {
		if tag.TagType != miniTag.TagType {
			return false
		}
	}
	if code&TagValue != 0 {
		if tag.TagValue != miniTag.TagValue {
			return false
		}
	}
	return true
}

func TestEncodeMiniTag(t *testing.T) {
	encoder := &codec.SimpleEncoder{}
	decoder := &codec.SimpleDecoder{}

	sideMiniTag := &MiniTag{
		MiniField: &MiniField{
			IsIPv6:     0,
			rawIP:      [net.IPv6len]byte{10, 11, 1, 123},
			L3EpcID:    15,
			VTAPID:     24,
			Protocol:   layers.IPProtocolTCP,
			ServerPort: 5324,
			Direction:  ClientToServer,
			TAPType:    CLOUD,
			ACLGID:     16,
			TagType:    TAG_TYPE_TUNNEL_IP_ID,
			TagValue:   18,
		},
		Code: IP | L3EpcID | VTAPID | Protocol | ServerPort | Direction | TAPType | ACLGID | TagType | TagValue,
	}

	pbMtagE := &pb.MiniTag{}
	sideMiniTag.WriteToPB(pbMtagE)
	encoder.WritePB(pbMtagE)

	decoder.Init(encoder.Bytes())
	pbMtagD := &pb.MiniTag{}
	decoder.ReadPB(pbMtagD)

	sideTag := &Tag{Field: &Field{}}
	sideTag.ReadFromPB(pbMtagD)

	if !checkTagAndMiniTagEqual(sideTag, sideMiniTag) {
		t.Error("mini tag and tag mismatch")
		t.Error("tag:     ", sideTag)
		t.Error("mini tag:", sideMiniTag)
	}

	encoder.Reset()

	edgeMiniTag := &MiniTag{
		MiniField: &MiniField{
			IsIPv6:     1,
			rawIP:      [net.IPv6len]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			rawIP1:     [net.IPv6len]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
			L3EpcID:    15,
			L3EpcID1:   16,
			VTAPID:     24,
			Protocol:   layers.IPProtocolTCP,
			ServerPort: 5324,
			Direction:  ClientToServer,
			TAPType:    CLOUD,
			ACLGID:     16,
			TagType:    TAG_TYPE_TUNNEL_IP_ID,
			TagValue:   18,
		},
		Code: IPPath | L3EpcIDPath | VTAPID | Protocol | ServerPort | Direction | TAPType | ACLGID | TagType | TagValue,
	}

	pbMtagE.Reset()
	edgeMiniTag.WriteToPB(pbMtagE)
	encoder.WritePB(pbMtagE)
	decoder.Init(encoder.Bytes())

	pbMtagD.Reset()
	edgeTag := &Tag{Field: &Field{}}
	decoder.ReadPB(pbMtagD)
	edgeTag.ReadFromPB(pbMtagD)

	if !checkTagAndMiniTagEqual(edgeTag, edgeMiniTag) {
		t.Error("mini tag and tag mismatch")
		t.Error("tag:     ", edgeTag)
		t.Error("mini tag:", edgeMiniTag)
	}

	encoder.Reset()
	edgeMiniTag.Direction = ServerToClient

	pbMtagE.Reset()
	edgeMiniTag.WriteToPB(pbMtagE)
	encoder.WritePB(pbMtagE)
	decoder.Init(encoder.Bytes())

	pbMtagD.Reset()
	decoder.ReadPB(pbMtagD)
	edgeTag = &Tag{Field: &Field{}}
	edgeTag.ReadFromPB(pbMtagD)

	if !checkTagAndMiniTagEqual(edgeTag, edgeMiniTag) {
		t.Error("mini tag and tag mismatch")
		t.Error("tag:     ", edgeTag)
		t.Error("mini tag:", edgeMiniTag)
	}
}

func TestDirectionEnum(t *testing.T) {
	clients := []DirectionEnum{ClientToServer, ClientNodeToServer, ClientHypervisorToServer, ClientGatewayHypervisorToServer, ClientGatewayToServer}
	for _, c := range clients {
		if !c.IsClientToServer() {
			t.Errorf("%v is client to server", c)
		}
		if c.IsServerToClient() {
			t.Errorf("%v is not server to client", c)
		}
	}

	servers := []DirectionEnum{ServerToClient, ServerNodeToClient, ServerHypervisorToClient, ServerGatewayHypervisorToClient, ServerGatewayToClient}
	for _, c := range servers {
		if !c.IsServerToClient() {
			t.Errorf("%v is server to client", c)
		}
		if c.IsClientToServer() {
			t.Errorf("%v is not client to server", c)
		}
	}
}

func TestDirectionToTAPSide(t *testing.T) {
	directions := []DirectionEnum{
		ClientToServer, ServerToClient, LocalToLocal,
		ClientNodeToServer, ServerNodeToClient,
		ClientHypervisorToServer, ServerHypervisorToClient,
		ClientGatewayHypervisorToServer, ServerGatewayHypervisorToClient,
		ClientGatewayToServer, ServerGatewayToClient,
	}
	tapSides := []TAPSideEnum{
		Client, Server, Local,
		ClientNode, ServerNode,
		ClientHypervisor, ServerHypervisor,
		ClientGatewayHypervisor, ServerGatewayHypervisor,
		ClientGateway, ServerGateway,
	}
	for i, d := range directions {
		if to := d.ToTAPSide(); to != tapSides[i] {
			t.Errorf("direction %v to tapSide %v error, should be %v", d, to, tapSides[i])
		}
	}
}

func TestPutTAPPort(t *testing.T) {
	bs := make([]byte, 16)
	for _, tc := range []struct {
		input  uint64
		output string
	}{
		{0, "00000000"},
		{1, "00000001"},
		{15, "0000000f"},
		{65535, "0000ffff"},
		{65535 << 8, "00ffff00"},
	} {
		putTAPPort(bs, tc.input)
		if string(bs[:TAP_PORT_STR_LEN]) != tc.output {
			t.Errorf("putTAPPort(%d)应为%s实为%s", tc.input, tc.output, bs[:TAP_PORT_STR_LEN])
		}
	}
}
