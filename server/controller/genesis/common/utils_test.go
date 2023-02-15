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

package common

import (
	"testing"

	"github.com/deepflowio/deepflow/server/controller/common"
	. "github.com/smartystreets/goconvey/convey"
)

func TestParseIPOutput(t *testing.T) {
	Convey("TestParseIPOutput", t, func() {
		interfaceStr := "8: veth1513f4b@if7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default\n    link/ether aa:b0:09:22:fe:0f brd ff:ff:ff:ff:ff:ff link-netnsid 0\n    inet6 fe80::a8b0:9ff:fe22:fe0f/64 scope link\n       valid_lft forever preferred_lft forever\n9: flannel.1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UNKNOWN group default\n    link/ether 02:89:73:fc:74:a2 brd ff:ff:ff:ff:ff:ff\n    inet 10.244.0.0/32 scope global flannel.1\n       valid_lft forever preferred_lft forever\n    inet6 fe80::89:73ff:fefc:74a2/64 scope link\n       valid_lft forever preferred_lft forever\n10: cni0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UP group default qlen 1000\n    link/ether 62:fe:f5:45:bb:4f brd ff:ff:ff:ff:ff:ff\n    inet 10.244.0.1/24 scope global cni0\n       valid_lft forever preferred_lft forever\n    inet6 fe80::60fe:f5ff:fe45:bb4f/64 scope link\n       valid_lft forever preferred_lft forever\n12: vethb3acc59b@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue master cni0 state UP group default\n    link/ether 62:68:2d:ae:f7:56 brd ff:ff:ff:ff:ff:ff link-netnsid 2\n    inet6 fe80::6068:2dff:feae:f756/64 scope link\n       valid_lft forever preferred_lft forever\n13: vethc7918489@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue master cni0 state UP group default\n    link/ether 12:cb:5b:97:37:a2 brd ff:ff:ff:ff:ff:ff link-netnsid 3\n    inet6 fe80::10cb:5bff:fe97:37a2/64 scope link\n       valid_lft forever preferred_lft forever\n14: vetha196f29d@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue master cni0 state UP group default\n    link/ether e2:f6:f7:03:4a:8d brd ff:ff:ff:ff:ff:ff link-netnsid 4\n    inet6 fe80::e0f6:f7ff:fe03:4a8d/64 scope link\n       valid_lft forever preferred_lft forever\n19: veth67973efb@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue master cni0 state UP group default\n    link/ether 4e:f8:5c:4c:31:26 brd ff:ff:ff:ff:ff:ff link-netnsid 5\n    inet6 fe80::4cf8:5cff:fe4c:3126/64 scope link\n       valid_lft forever preferred_lft forever\n1: Loopback Pseudo-Interface 1: <LOOPBACK|MULTICAST|UP> mtu -1 qdisc noqueue state UNKNOWN group default qlen 1000\n    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n    inet6 ::1/128 scope host Loopback Pseudo-Interface 1\n       valid_lft forever preferred_lft forever\n    inet 127.0.0.1/8 scope host Loopback Pseudo-Interface 1\n       valid_lft forever preferred_lft forever\n15: isatap.{E1B4E86B-9458-4952-8BF8-60F397906E97}: <MULTICAST|POINTTOPOINT> mtu 1280 qdisc noqueue state UNKNOWN group default qlen 1000\n    link/ether 00:00:00:00:00:00:00:e0 brd ff:ff:ff:ff:ff:ff\n    inet6 fe80::5efe:ac1d:c8c8/128 scope link isatap.{E1B4E86B-9458-4952-8BF8-60F397906E97}\n       valid_lft forever preferred_lft forever\n17: isatap.{6C8CB667-5798-4304-8282-A829AE964848}: <MULTICAST|POINTTOPOINT> mtu 1280 qdisc noqueue state UNKNOWN group default qlen 1000\n    link/ether 00:00:00:00:00:00:00:e0 brd ff:ff:ff:ff:ff:ff\n    inet6 fe80::5efe:a32:c8c8/128 scope link isatap.{6C8CB667-5798-4304-8282-A829AE964848}\n       valid_lft forever preferred_lft forevr\n5: tunl0@NONE: \u003cNOARP,UP,LOWER_UP\u003e mtu 1480 qdisc noqueue state UNKNOWN group default qlen 1000\n    link/ipip 0.0.0.0 brd 0.0.0.0\n    inet 100.84.241.0/32 scope global tunl0\n       valid_lft forever preferred_lft forever\n"
		parseInterface, _ := ParseIPOutput(interfaceStr)
		Convey("ParseIPOutput ips number should be equal", func() {
			So(len(parseInterface), ShouldEqual, 11)
			So(len(parseInterface[1].IPs), ShouldEqual, 2)
			So(parseInterface[1].IPs[0].MaskLen, ShouldEqual, 32)
			So(parseInterface[1].IPs[0].Address, ShouldEqual, "10.244.0.0")
			So(parseInterface[1].IPs[1].MaskLen, ShouldEqual, 64)
			So(parseInterface[1].IPs[1].Address, ShouldEqual, "fe80::89:73ff:fefc:74a2")
			So(len(parseInterface[2].IPs), ShouldEqual, 2)
			So(parseInterface[2].IPs[0].MaskLen, ShouldEqual, 24)
			So(parseInterface[2].IPs[0].Address, ShouldEqual, "10.244.0.1")
			So(parseInterface[2].IPs[1].MaskLen, ShouldEqual, 64)
			So(parseInterface[2].IPs[1].Address, ShouldEqual, "fe80::60fe:f5ff:fe45:bb4f")
			So(parseInterface[0].Index, ShouldEqual, 8)
			So(parseInterface[0].PeerIndex, ShouldEqual, 7)
			So(parseInterface[0].Name, ShouldEqual, "veth1513f4b")
			So(parseInterface[0].MAC, ShouldEqual, "aa:b0:09:22:fe:0f")
			So(parseInterface[0].IPs[0].MaskLen, ShouldEqual, 64)
			So(parseInterface[0].IPs[0].Scope, ShouldEqual, "link")
			So(parseInterface[0].IPs[0].Address, ShouldEqual, "fe80::a8b0:9ff:fe22:fe0f")
			So(parseInterface[6].Index, ShouldEqual, 19)
			So(parseInterface[6].PeerIndex, ShouldEqual, 3)
			So(parseInterface[6].Name, ShouldEqual, "veth67973efb")
			So(parseInterface[6].MAC, ShouldEqual, "4e:f8:5c:4c:31:26")
			So(parseInterface[6].IPs[0].MaskLen, ShouldEqual, 64)
			So(parseInterface[6].IPs[0].Scope, ShouldEqual, "link")
			So(parseInterface[6].IPs[0].Address, ShouldEqual, "fe80::4cf8:5cff:fe4c:3126")
			So(parseInterface[7].Index, ShouldEqual, 1)
			So(parseInterface[7].Name, ShouldEqual, "Loopback Pseudo-Interface 1")
			So(parseInterface[7].MAC, ShouldEqual, "00:00:00:00:00:00")
			So(parseInterface[7].IPs[0].MaskLen, ShouldEqual, 128)
			So(parseInterface[7].IPs[0].Scope, ShouldEqual, "host")
			So(parseInterface[7].IPs[0].Address, ShouldEqual, "::1")
			So(parseInterface[7].IPs[1].MaskLen, ShouldEqual, 8)
			So(parseInterface[7].IPs[1].Scope, ShouldEqual, "host")
			So(parseInterface[7].IPs[1].Address, ShouldEqual, "127.0.0.1")
			So(parseInterface[8].Index, ShouldEqual, 15)
			So(parseInterface[8].Name, ShouldEqual, "isatap.{E1B4E86B-9458-4952-8BF8-60F397906E97}")
			So(parseInterface[8].IPs[0].MaskLen, ShouldEqual, 128)
			So(parseInterface[8].IPs[0].Scope, ShouldEqual, "link")
			So(parseInterface[8].IPs[0].Address, ShouldEqual, "fe80::5efe:ac1d:c8c8")
			So(parseInterface[9].Index, ShouldEqual, 17)
			So(parseInterface[9].Name, ShouldEqual, "isatap.{6C8CB667-5798-4304-8282-A829AE964848}")
			So(parseInterface[9].IPs[0].MaskLen, ShouldEqual, 128)
			So(parseInterface[9].IPs[0].Scope, ShouldEqual, "link")
			So(parseInterface[9].IPs[0].Address, ShouldEqual, "fe80::5efe:a32:c8c8")
			So(parseInterface[10].Index, ShouldEqual, 5)
			So(parseInterface[10].Name, ShouldEqual, "tunl0")
			So(parseInterface[10].MAC, ShouldEqual, "00:00:00:00:00:00")
			So(parseInterface[10].IPs[0].MaskLen, ShouldEqual, 32)
			So(parseInterface[10].IPs[0].Scope, ShouldEqual, "global")
			So(parseInterface[10].IPs[0].Address, ShouldEqual, "100.84.241.0")
		})
	})
}

func TestParseCSV(t *testing.T) {
	CSVStr := "_uuid,name,interfaces\n9f4ca795-6f71-40c7-890a-3601755bd1e5,br-p1p2,\n0dda1b31-75e2-4218-a935-784e14a79133,br-int,\nc911fefb-0185-4650-8543-d6c7e6d5be89,br-em2,3e878ea4-e494-43f5-adc0-969b4479ed83 5b92773a-6781-4364-8497-ff28773e3ae4"
	Convey("TestParseCSV-1", t, func() {
		csv, _ := ParseCSV(CSVStr)
		Convey("ParseCSV-1 items should be equal", func() {
			So(len(csv), ShouldEqual, 3)
			So(csv[0]["name"], ShouldEqual, "br-p1p2")
			So(csv[0]["_uuid"], ShouldEqual, "9f4ca795-6f71-40c7-890a-3601755bd1e5")
			So(csv[0]["interfaces"], ShouldEqual, "")
			So(csv[1]["name"], ShouldEqual, "br-int")
			So(csv[1]["_uuid"], ShouldEqual, "0dda1b31-75e2-4218-a935-784e14a79133")
			So(csv[1]["interfaces"], ShouldEqual, "")
			So(csv[2]["name"], ShouldEqual, "br-em2")
			So(csv[2]["_uuid"], ShouldEqual, "c911fefb-0185-4650-8543-d6c7e6d5be89")
			So(csv[2]["interfaces"], ShouldEqual, "3e878ea4-e494-43f5-adc0-969b4479ed83 5b92773a-6781-4364-8497-ff28773e3ae4")
		})
	})
	Convey("TestParseCSV-2", t, func() {
		csv, _ := ParseCSV(CSVStr, "name")
		Convey("ParseCSV-2 items should be equal", func() {
			So(len(csv), ShouldEqual, 3)
			So(csv[0]["name"], ShouldEqual, "br-p1p2")
			So(csv[1]["name"], ShouldEqual, "br-int")
			So(csv[2]["name"], ShouldEqual, "br-em2")
		})
	})
}

func TestParseCSVWithKey(t *testing.T) {
	CSVStr := "_uuid,name,interfaces\n9f4ca795-6f71-40c7-890a-3601755bd1e5,br-p1p2,\n0dda1b31-75e2-4218-a935-784e14a79133,br-int,\nc911fefb-0185-4650-8543-d6c7e6d5be89,br-em2,3e878ea4-e494-43f5-adc0-969b4479ed83 5b92773a-6781-4364-8497-ff28773e3ae4"
	Convey("TestParseCSVWithKey-1", t, func() {
		csv, _ := ParseCSVWithKey(CSVStr, "name")
		Convey("ParseCSVWithKey-1 items should be equal", func() {
			So(len(csv), ShouldEqual, 3)
			So(csv["br-p1p2"]["name"], ShouldEqual, "br-p1p2")
			So(csv["br-p1p2"]["_uuid"], ShouldEqual, "9f4ca795-6f71-40c7-890a-3601755bd1e5")
			So(csv["br-p1p2"]["interfaces"], ShouldEqual, "")
			So(csv["br-int"]["name"], ShouldEqual, "br-int")
			So(csv["br-int"]["_uuid"], ShouldEqual, "0dda1b31-75e2-4218-a935-784e14a79133")
			So(csv["br-int"]["interfaces"], ShouldEqual, "")
			So(csv["br-em2"]["name"], ShouldEqual, "br-em2")
			So(csv["br-em2"]["_uuid"], ShouldEqual, "c911fefb-0185-4650-8543-d6c7e6d5be89")
			So(csv["br-em2"]["interfaces"], ShouldEqual, "3e878ea4-e494-43f5-adc0-969b4479ed83 5b92773a-6781-4364-8497-ff28773e3ae4")
		})
	})
	Convey("TestParseCSVWithKey-2", t, func() {
		csv, _ := ParseCSVWithKey(CSVStr, "name", "name")
		Convey("ParseCSVWithKey-2 items should be equal", func() {
			So(len(csv), ShouldEqual, 3)
			So(csv["br-p1p2"]["name"], ShouldEqual, "br-p1p2")
			So(csv["br-int"]["name"], ShouldEqual, "br-int")
			So(csv["br-em2"]["name"], ShouldEqual, "br-em2")
		})
	})
}

func TestParseKVString(t *testing.T) {
	KVStr := "attached-mac=fa:16:3e:a8:7d:f1 iface-id=46176ea6-b476-4ccf-be60-b579e32393b5 iface-status=active vm-uuid=1db6d632-67ef-4dc1-8b0a-5be33497650f novalue"
	Convey("TestParseKVString", t, func() {
		options, _ := ParseKVString(KVStr)
		Convey("ParseKVString items should be equal", func() {
			So(len(options), ShouldEqual, 5)
			So(options["attached-mac"], ShouldEqual, "fa:16:3e:a8:7d:f1")
			So(options["novalue"], ShouldEqual, "")
		})
	})
}

func TestParseBrctlShow(t *testing.T) {
	BrStr := "bridge name\tbridge id\t\tSTP enabled\tinterfaces\nbr0\t\t8000.000af75ef9e2\tno\t\tp5p2\n\t\t\t\t\t\tvnet0\n\t\t\t\t\t\tvnet12\n\t\t\t\t\t\tvnet18\n\t\t\t\t\t\tvnet3\n\t\t\t\t\t\tvnet6\n\t\t\t\t\t\tvnet9\nbr1\t\t8000.fe54005d366d\tno\t\tvnet1\n\t\t\t\t\t\tvnet10\n\t\t\t\t\t\tvnet13\n\t\t\t\t\t\tvnet19\n\t\t\t\t\t\tvnet4\n\t\t\t\t\t\tvnet7\nbr2\t\t8000.fe54001f3304\tno\t\tvnet11\n\t\t\t\t\t\tvnet14\n\t\t\t\t\t\tvnet2\n\t\t\t\t\t\tvnet20\n\t\t\t\t\t\tvnet5\n\t\t\t\t\t\tvnet8\ndocker0\t\t8000.02426b7d5755\tno\t\t\n"
	Convey("TestParseBrctlShow", t, func() {
		brs, _ := ParseBrctlShow(BrStr)
		Convey("ParseBrctlShow items should be equal", func() {
			So(len(brs), ShouldEqual, 4)
			So(len(brs["br0"]), ShouldEqual, 7)
			So(brs["br0"][0], ShouldEqual, "p5p2")
			So(brs["br0"][3], ShouldEqual, "vnet18")
			So(brs["br0"][6], ShouldEqual, "vnet9")
			So(len(brs["br1"]), ShouldEqual, 6)
			So(brs["br1"][0], ShouldEqual, "vnet1")
			So(brs["br1"][2], ShouldEqual, "vnet13")
			So(brs["br1"][5], ShouldEqual, "vnet7")
			So(len(brs["br2"]), ShouldEqual, 6)
			So(brs["br2"][0], ShouldEqual, "vnet11")
			So(brs["br2"][2], ShouldEqual, "vnet2")
			So(brs["br2"][5], ShouldEqual, "vnet8")
			So(len(brs["docker0"]), ShouldEqual, 0)
		})
	})
}

func TestParseVLANConfig(t *testing.T) {
	vlanStr := "VLAN Dev name    | VLAN ID\nName-Type: VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD\np7p1.259       | 259  | p7p1\np7p1.260       | 260  | p7p1\np7p1.261       | 261  | p7p1\np7p1.262       | 262  | p7p1\np7p1.263       | 263  | p7p1\np7p1.264       | 264  | p7p1\np7p1.265       | 265  | p7p1\np7p1.266       | 266  | p7p1\np4p1.770       | 770  | p4p1\np4p1.771       | 771  | p4p1\np4p1.772       | 772  | p4p1\np4p1.773       | 773  | p4p1\np4p1.774       | 774  | p4p1\np4p1.775       | 775  | p4p1\np4p1.776       | 776  | p4p1\np4p1.777       | 777  | p4p1\np4p1.778       | 778  | p4p1\n"
	Convey("TestParseVLANConfig", t, func() {
		vlans, _ := ParseVLANConfig(vlanStr)
		Convey("ParseVLANConfig items should be equal", func() {
			So(len(vlans), ShouldEqual, 17)
			So(vlans["p7p1.259"], ShouldEqual, 259)
			So(vlans["p7p1.260"], ShouldEqual, 260)
			So(vlans["p7p1.261"], ShouldEqual, 261)
			So(vlans["p7p1.262"], ShouldEqual, 262)
			So(vlans["p7p1.263"], ShouldEqual, 263)
			So(vlans["p7p1.264"], ShouldEqual, 264)
			So(vlans["p7p1.265"], ShouldEqual, 265)
			So(vlans["p7p1.266"], ShouldEqual, 266)
			So(vlans["p4p1.770"], ShouldEqual, 770)
			So(vlans["p4p1.771"], ShouldEqual, 771)
			So(vlans["p4p1.772"], ShouldEqual, 772)
			So(vlans["p4p1.773"], ShouldEqual, 773)
			So(vlans["p4p1.774"], ShouldEqual, 774)
			So(vlans["p4p1.775"], ShouldEqual, 775)
			So(vlans["p4p1.776"], ShouldEqual, 776)
			So(vlans["p4p1.777"], ShouldEqual, 777)
			So(vlans["p4p1.778"], ShouldEqual, 778)
		})
	})
}

func TestParseVMStates(t *testing.T) {
	VMStr := " Id    名称                         状态\n----------------------------------------------------\n 1     instance-00000033              关闭\n 3     instance-00000023              running\n 4     instance-00000022              关闭\n 32    instance-00000076              running\n 34    instance-00000025              shut off\n 46    instance-00000086              running\n 49    instance-00000099              running\n 50    instance-0000009a              running\n 58    instance-000000a8              running\n 59    instance-000000a9              running\n 61    instance-000000b1              running\n 62    instance-000000b3              running\n"
	Convey("TestParseVMStates", t, func() {
		states, _ := ParseVMStates(VMStr)
		Convey("ParseVMStates items should be equal", func() {
			So(len(states), ShouldEqual, 12)
			So(states["instance-00000033"], ShouldEqual, common.VM_STATE_STOPPED)
			So(states["instance-00000025"], ShouldEqual, common.VM_STATE_STOPPED)
			So(states["instance-00000076"], ShouldEqual, common.VM_STATE_RUNNING)
		})
	})
}

func TestParseVMXml(t *testing.T) {
	XMLStr := `<domains>\n<domain type='kvm'>\n  <name>instance-00000064</name>\n  <uuid>a51e6527-bd5e-42c2-81be-fee17d814706</uuid>\n  <metadata>\n    <nova:instance xmlns:nova="http://openstack.org/xmlns/libvirt/nova/1.0">\n      <nova:name>test-vm-liqian</nova:name>\n      <nova:owner>\n        <nova:user uuid="417a8402bfc64f4abb67f68a8a0fdcff">bangongfuwu</nova:user>\n        <nova:project uuid="7e39057dbe2042e4b3b188678f22648e">NSLS</nova:project>\n      </nova:owner>\n    </nova:instance>\n  </metadata>\n  <devices>\n    <interface type='bridge'>\n      <mac address='fa:16:3e:59:b5:10'/>\n      <source bridge='qbr155abd89-91'/>\n      <target dev='tap155abd89-91'/>\n      <model type='virtio'/>\n      <address type='pci' domain='0x0000' bus='0x00' slot='0x03' function='0x0'/>\n    </interface>\n  </devices>\n</domain>\n<!--\nWARNING: THIS IS AN AUTO-GENERATED FILE. CHANGES TO IT ARE LIKELY TO BE\nOVERWRITTEN AND LOST. Changes to this xml configuration should be made using:\n  virsh edit instance-00000065\nor other application using the libvirt API.\n-->\n<domain type='kvm'>\n  <name>instance-00000065</name>\n  <uuid>75e9bb32-09c8-48e9-93bc-0330686702f3</uuid>\n  <metadata>\n    <nova:instance xmlns:nova="http://openstack.org/xmlns/libvirt/nova/1.0">\n      <nova:name>lbq-vm-vxlan-1</nova:name>\n      <nova:owner>\n        <nova:user uuid="417a8402bfc64f4abb67f68a8a0fdcff">bangongfuwu</nova:user>\n        <nova:project uuid="7e39057dbe2042e4b3b188678f22648e">NSLS</nova:project>\n      </nova:owner>\n    </nova:instance>\n  </metadata>\n  <devices>\n    <interface type='bridge'>\n      <mac address='fa:16:3e:38:a5:48'/>\n      <source bridge='qbr717a30a1-db'/>\n      <target dev='tap717a30a1-db'/>\n      <model type='virtio'/>\n      <address type='pci' domain='0x0000' bus='0x00' slot='0x03' function='0x0'/>\n    </interface>\n    <interface type='bridge'>\n      <mac address='fa:16:3e:8f:78:2b'/>\n      <source bridge='qbr27e9b93c-93'/>\n      <target dev='tap27e9b93c-93'/>\n      <model type='virtio'/>\n      <address type='pci' domain='0x0000' bus='0x00' slot='0x06' function='0x0'/>\n    </interface>\n  </devices>\n</domain>\n</domains>\n`
	Convey("TestParseVMXml", t, func() {
		xmls, _ := ParseVMXml(XMLStr)
		Convey("ParseVMXml items should be equal", func() {
			So(len(xmls), ShouldEqual, 2)
			So(xmls[0].UUID, ShouldEqual, "a51e6527-bd5e-42c2-81be-fee17d814706")
			So(xmls[0].Label, ShouldEqual, "instance-00000064")
			So(xmls[0].Name, ShouldEqual, "test-vm-liqian")
			So(xmls[0].VPC.UUID, ShouldEqual, "7e39057d-be20-42e4-b3b1-88678f22648e")
			So(xmls[0].VPC.Name, ShouldEqual, "NSLS")
			So(xmls[0].Interfaces[0].Target, ShouldEqual, "tap155abd89-91")
			So(xmls[0].Interfaces[0].Mac, ShouldEqual, "fa:16:3e:59:b5:10")
			So(xmls[1].UUID, ShouldEqual, "75e9bb32-09c8-48e9-93bc-0330686702f3")
			So(xmls[1].Label, ShouldEqual, "instance-00000065")
			So(xmls[1].Name, ShouldEqual, "lbq-vm-vxlan-1")
			So(xmls[1].VPC.UUID, ShouldEqual, "7e39057d-be20-42e4-b3b1-88678f22648e")
			So(xmls[1].VPC.Name, ShouldEqual, "NSLS")
			So(xmls[1].Interfaces[0].Target, ShouldEqual, "tap717a30a1-db")
			So(xmls[1].Interfaces[0].Mac, ShouldEqual, "fa:16:3e:38:a5:48")
			So(xmls[1].Interfaces[1].Target, ShouldEqual, "tap27e9b93c-93")
			So(xmls[1].Interfaces[1].Mac, ShouldEqual, "fa:16:3e:8f:78:2b")
		})
	})
}
