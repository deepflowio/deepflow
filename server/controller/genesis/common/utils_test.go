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

	. "github.com/smartystreets/goconvey/convey"
)

func TestParseIPOutput(t *testing.T) {
	Convey("TestParseIPOutput", t, func() {
		interfaceStr := "8: veth1513f4b@if7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default\n    link/ether aa:b0:09:22:fe:0f brd ff:ff:ff:ff:ff:ff link-netnsid 0\n    inet6 fe80::a8b0:9ff:fe22:fe0f/64 scope link\n       valid_lft forever preferred_lft forever\n9: flannel.1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UNKNOWN group default\n    link/ether 02:89:73:fc:74:a2 brd ff:ff:ff:ff:ff:ff\n    inet 10.244.0.0/32 scope global flannel.1\n       valid_lft forever preferred_lft forever\n    inet6 fe80::89:73ff:fefc:74a2/64 scope link\n       valid_lft forever preferred_lft forever\n10: cni0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UP group default qlen 1000\n    link/ether 62:fe:f5:45:bb:4f brd ff:ff:ff:ff:ff:ff\n    inet 10.244.0.1/24 scope global cni0\n       valid_lft forever preferred_lft forever\n    inet6 fe80::60fe:f5ff:fe45:bb4f/64 scope link\n       valid_lft forever preferred_lft forever\n12: vethb3acc59b@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue master cni0 state UP group default\n    link/ether 62:68:2d:ae:f7:56 brd ff:ff:ff:ff:ff:ff link-netnsid 2\n    inet6 fe80::6068:2dff:feae:f756/64 scope link\n       valid_lft forever preferred_lft forever\n13: vethc7918489@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue master cni0 state UP group default\n    link/ether 12:cb:5b:97:37:a2 brd ff:ff:ff:ff:ff:ff link-netnsid 3\n    inet6 fe80::10cb:5bff:fe97:37a2/64 scope link\n       valid_lft forever preferred_lft forever\n14: vetha196f29d@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue master cni0 state UP group default\n    link/ether e2:f6:f7:03:4a:8d brd ff:ff:ff:ff:ff:ff link-netnsid 4\n    inet6 fe80::e0f6:f7ff:fe03:4a8d/64 scope link\n       valid_lft forever preferred_lft forever\n19: veth67973efb@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue master cni0 state UP group default\n    link/ether 4e:f8:5c:4c:31:26 brd ff:ff:ff:ff:ff:ff link-netnsid 5\n    inet6 fe80::4cf8:5cff:fe4c:3126/64 scope link\n       valid_lft forever preferred_lft forever"
		parseInterface, _ := ParseIPOutput(interfaceStr)
		Convey("ParseIPOutput ips number should be equal", func() {
			So(len(parseInterface), ShouldEqual, 7)
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
		})
	})
}
