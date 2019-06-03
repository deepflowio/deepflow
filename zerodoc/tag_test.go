package zerodoc

import (
	"github.com/google/gopacket/layers"
	"testing"
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

func TestFastOrNormalID(t *testing.T) {
	f := Field{L3EpcID: 3, TAPType: ToR, L2EpcID: 2}
	if f.NewTag(L3EpcID|TAPType).GetFastID() == 0 {
		t.Error("FastID没有正确设置")
	}
	if f.NewTag(L3EpcID|L2EpcID).GetFastID() != 0 {
		t.Error("非FastID的Tag被设置了")
	}
}

func TestNegativeID(t *testing.T) {
	a := int16(30000)
	f := Field{L3EpcID: -1, L2EpcID: int16(a * 2), GroupID: -1}
	if f.NewTag(L3EpcID|L2EpcID|GroupID).ToKVString() != ",group_id=-1,l2_epc_id=60000,l3_epc_id=-1" {
		t.Error("int16值处理得不正确")
	}
}

func TestFill1(t *testing.T) {
	f := Field{}
	tag := &Tag{&f, 0, ""}
	tags := map[string]string{
		"ip": "1.1.1.1", "group_id": "0", "l2_epc_id": "-1", "l3_epc_id": "-3",
		"l2_device_id": "200", "l2_device_type": "1", "l3_device_id": "300", "l3_device_type": "5",
		"host": "3.3.3.3", "ip_1": "5.5.5.5", "group_id_1": "-2",
		"l2_epc_id_1": "21", "l3_epc_id_1": "31", "l2_device_id_1": "22", "l2_device_type_1": "7", "l3_device_id_1": "32", "l3_device_type_1": "9",
		"host_1": "5.5.5.5", "subnet_id_1": "2000", "direction": "c2s", "acl_gid": "400", "vlan_id": "500",
		"protocol": "4", "server_port": "9527", "tap_type": "0", "subnet_id": "1001", "acl_direction": "fwd", "scope": "in_epc", "country": "CHN", "region": "北京", "isp": "移动",
	}

	tag.Fill(0xffffffffffffffff, tags)

	if tag.IP != 16843009 {
		t.Error("ip 处理错误")
	}
	if tag.GroupID != 0 {
		t.Error("GroupID 处理错误")
	}
	if tag.L2EpcID != -1 {
		t.Error("L2EpcID 处理错误")
	}
	if tag.L3EpcID != -3 {
		t.Error("L3EpcID 处理错误")
	}
	if tag.L2DeviceID != 200 {
		t.Error("L2DeviceID 处理错误")
	}
	if tag.L3DeviceID != 300 {
		t.Error("L3DeviceID 处理错误")
	}
	if tag.L2DeviceType != DeviceType(1) {
		t.Error("L2DeviceType 处理错误")
	}
	if tag.L3DeviceType != DeviceType(5) {
		t.Error("L3DeviceType 处理错误")
	}
	if tag.Host != 50529027 {
		t.Error("Host 处理错误")
	}
	if tag.IP1 != 84215045 {
		t.Error("IP1 处理错误")
	}
	if tag.GroupID1 != -2 {
		t.Error("GroupID1 处理错误")
	}
	if tag.L2EpcID1 != 21 {
		t.Error("L2EpcID1 处理错误")
	}
	if tag.L3EpcID1 != 31 {
		t.Error("L3EpcID1 处理错误")
	}
	if tag.L2DeviceID1 != 22 {
		t.Error("L2DeviceID1 处理错误")
	}
	if tag.L3DeviceID1 != 32 {
		t.Error("L3DeviceID1 处理错误")
	}
	if tag.L2DeviceType1 != DeviceType(7) {
		t.Error("L2DeviceType1 处理错误")
	}
	if tag.L3DeviceType1 != DeviceType(9) {
		t.Error("L3DeviceType1 处理错误")
	}
	if tag.Host1 != 84215045 {
		t.Error("Host1 处理错误")
	}
	if tag.ACLGID != 400 {
		t.Error("ACLGID 处理错误")
	}
	if tag.VLANID != 500 {
		t.Error("VLANID 处理错误")
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
	if tag.ACLDirection != ACL_FORWARD {
		t.Error("ACLDirection 处理错误")
	}
	if tag.Scope != ScopeEnum(1) {
		t.Error("Scope 处理错误")
	}
	if tag.Country != 5 {
		t.Error("Country 处理错误")
	}
	if tag.Region != 8 {
		t.Error("Region 处理错误")
	}
	if tag.ISP != 8 {
		t.Error("ISP 处理错误")
	}
}

func TestFill0(t *testing.T) {
	f := Field{}
	tag := &Tag{&f, 0, ""}
	tags := map[string]string{
		"ip_0": "2.2.2.2", "group_id_0": "10", "l2_epc_id_0": "20", "l3_epc_id_0": "30",
		"l2_device_id_0": "201", "l2_device_type_0": "3", "l3_device_id_0": "301", "l3_device_type_0": "7",
		"host_0": "4.4.4.4", "subnet_id_0": "1000",
	}

	tag.Fill(0xffffffffffffffff, tags)
	if tag.IP != 33686018 {
		t.Error("ip 处理错误")
	}
	if tag.GroupID != 10 {
		t.Error("GroupID 处理错误")
	}
	if tag.L2EpcID != 20 {
		t.Error("L2EpcID 处理错误")
	}
	if tag.L3EpcID != 30 {
		t.Error("L3EpcID 处理错误")
	}
	if tag.L2DeviceID != 201 {
		t.Error("L2DeviceID 处理错误")
	}
	if tag.L2DeviceType != DeviceType(3) {
		t.Error("L2DeviceType 处理错误")
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
	if tag.Host != 67372036 {
		t.Error("Host 处理错误")
	}
}

func TestFillValues(t *testing.T) {
	f := Field{}
	tag := &Tag{&f, 0, ""}
	names := []string{"ip", "sum_packet", "server_port"}
	isTag := []bool{true, false, true}
	values := []interface{}{"1.1.1.1", int64(1000), "9527"}
	tag.FillValues(isTag, names, values)
	if tag.IP != 16843009 {
		t.Error("ip 处理错误")
	}
	if tag.ServerPort != 9527 {
		t.Error("ServerPort 处理错误")
	}
}
