package zerodoc

import (
	"math"
	"net"
	"sort"
	"strings"
	"testing"

	"github.com/google/gopacket/layers"

	"gitlab.x.lan/yunshan/droplet-libs/datatype"
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

func TestFillTag(t *testing.T) {
	f := Field{L3EpcID: 3}
	tag := &Tag{}
	f.FillTag(L3EpcID, tag)
	if tag.ToKVString() != ",l3_epc_id=3" {
		t.Error("FillTag处理不正确")
	}
}

func TestInt16Unmarshal(t *testing.T) {
	for i := math.MinInt16; i <= math.MaxInt16; i++ {
		v, _ := unmarshalUint16WithSpecialID(marshalUint16WithSpecialID(int16(i)))
		if int16(i) != v {
			t.Errorf("序列化反序列化[%d]不正确", i)
		}
	}
}

func TestNegativeID(t *testing.T) {
	f := Field{L3EpcID: datatype.EPC_FROM_DEEPFLOW, GroupID: datatype.GROUP_INTERNET}
	if f.NewTag(L3EpcID|GroupID).ToKVString() != ",group_id=-2,l3_epc_id=-1" {
		t.Error("int16值处理得不正确")
	}
	f = Field{L3EpcID: 32767, GroupID: -3}
	if f.NewTag(L3EpcID|GroupID).ToKVString() != ",group_id=65533,l3_epc_id=32767" {
		t.Error("int16值处理得不正确")
	}
}

func TestFill1(t *testing.T) {
	f := Field{}
	tag := &Tag{&f, 0, ""}
	tags := map[string]string{
		"ip": "1.1.1.1", "group_id": "-1", "l3_epc_id": "-3",
		"l3_device_id": "300", "l3_device_type": "5",
		"host_id": "33", "ip_1": "5.5.5.5", "group_id_1": "-2",
		"l3_epc_id_1": "31", "l3_device_id_1": "32", "l3_device_type_1": "9",
		"host_id_1": "55", "subnet_id_1": "2000", "direction": "c2s", "acl_gid": "400",
		"protocol": "4", "server_port": "9527", "tap_type": "0", "subnet_id": "1001", "pod_node_id": "1", "az_id": "132",
		"tag_type": "1", "tag_value": "北京",
	}

	if err := tag.Fill(tags); err != nil {
		t.Error(err)
	}

	if tag.IP != 16843009 {
		t.Error("ip 处理错误")
	}
	if tag.GroupID != datatype.EPC_FROM_DEEPFLOW {
		t.Error("GroupID 处理错误")
	}
	if tag.L3EpcID != -3 {
		t.Error("L3EpcID 处理错误")
	}
	if tag.L3DeviceID != 300 {
		t.Error("L3DeviceID 处理错误")
	}
	if tag.L3DeviceType != DeviceType(5) {
		t.Error("L3DeviceType 处理错误")
	}
	if tag.HostID != 33 {
		t.Error("HostID 处理错误")
	}
	if tag.IP1 != 84215045 {
		t.Error("IP1 处理错误")
	}
	if tag.GroupID1 != -2 {
		t.Error("GroupID1 处理错误")
	}
	if tag.L3EpcID1 != 31 {
		t.Error("L3EpcID1 处理错误")
	}
	if tag.L3DeviceID1 != 32 {
		t.Error("L3DeviceID1 处理错误")
	}
	if tag.L3DeviceType1 != DeviceType(9) {
		t.Error("L3DeviceType1 处理错误")
	}
	if tag.HostID1 != 55 {
		t.Error("HostID1 处理错误")
	}
	if tag.ACLGID != 400 {
		t.Error("ACLGID 处理错误")
	}
	if tag.Direction != ClientToServer {
		t.Error("Direction 处理错误")
	}
	if tag.Protocol != layers.IPProtocol(4) {
		t.Error("Protocol 处理错误")
	}
	if tag.ServerPort != 9527 {
		t.Error("ServerPort 处理错误")
	}
	if tag.SubnetID != 1001 {
		t.Error("SubnetID 处理错误")
	}
	if tag.SubnetID1 != 2000 {
		t.Error("SubnetID1 处理错误")
	}
	if tag.TAPType != TAPTypeEnum(0) {
		t.Error("TAPType 处理错误")
	}
	if tag.PodNodeID != 1 {
		t.Error("PodNodeID 处理错误")
	}
	if tag.AZID != 132 {
		t.Error("AZID 处理错误")
	}
	if tag.TagType != 1 {
		t.Error("TagType 处理错误")
	}
	if tag.TagValue != 8 {
		t.Error("TagValue 处理错误:", tag.TagValue)
	}
}

func TestFill0(t *testing.T) {
	f := Field{}
	tag := &Tag{&f, 0, ""}
	tags := map[string]string{
		"ip_0": "2.2.2.2", "group_id_0": "10", "l3_epc_id_0": "30",
		"l3_device_id_0": "301", "l3_device_type_0": "7",
		"host_id_0": "4444", "subnet_id_0": "1000",
	}

	tag.Fill(tags)
	if tag.IP != 33686018 {
		t.Error("ip 处理错误")
	}
	if tag.GroupID != 10 {
		t.Error("GroupID 处理错误")
	}
	if tag.L3EpcID != 30 {
		t.Error("L3EpcID 处理错误")
	}
	if tag.L3DeviceID != 301 {
		t.Error("L3DeviceID 处理错误")
	}
	if tag.L3DeviceType != DeviceType(7) {
		t.Error("L3DeviceType 处理错误")
	}
	if tag.SubnetID != 1000 {
		t.Error("SubnetID 处理错误")
	}
	if tag.HostID != 4444 {
		t.Error("Host ID 处理错误")
	}
}

func TestFillValues(t *testing.T) {
	f := Field{}
	tag := &Tag{&f, 0, ""}
	names := []string{"ip", "sum_packet", "server_port"}
	values := []interface{}{"1.1.1.1", int64(1000), "9527"}
	tag.FillValues(GetColumnIDs(names), values)
	if tag.IP != 16843009 {
		t.Error("ip 处理错误")
	}
	if tag.ServerPort != 9527 {
		t.Error("ServerPort 处理错误")
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
	tag.Code = ^(GroupIDPath | HostIDPath | IPPath | L3DevicePath | L3EpcIDPath | RegionIDPath | SubnetIDPath | PodNodeIDPath | AZIDPath)

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

	tag.Code = ^(GroupID | HostID | IP | L3Device | L3EpcID | RegionID | SubnetID | PodNodeID | AZID)
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
