/*
 * Copyright (c) 2024 Yunshan Networks
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

package datatype

import "testing"

func TestIP(t *testing.T) {
	ipAddr := NewIPFromString("127.0.0.1")
	ipAddr1 := NewIPFromString("127.0.0.2")
	if ipAddr == nil {
		t.Error("解析IP string失败")
	}
	if ipAddr.String() != "127.0.0.1" {
		t.Error("IP转string失败，应为127.0.0.1，实为", ipAddr.String())
	}
	if ipAddr.Int() != 2130706433 {
		t.Error("IP转uint32失败，应为2130706433，实为", ipAddr.Int())
	}
	ipAddr = NewIPFromInt(4294967295)
	if ipAddr == nil {
		t.Error("解析IP uint32失败")
	}
	if ipAddr.String() != "255.255.255.255" {
		t.Error("IP转string失败，应为255.255.255.255，实为", ipAddr.String())
	}
	if ipAddr.Int() != 4294967295 {
		t.Error("IP转uint32失败，应为4294967295，实为", ipAddr.Int())
	}
	if ipAddr.Equals(ipAddr1) {
		t.Error("Equals 实现不正确")
	}
}

func TestMAC(t *testing.T) {
	macAddr := NewMACAddrFromString("11:22:33:44:55:66")
	macAddr1 := NewMACAddrFromString("22:33:44:55:66:77")

	if macAddr == nil {
		t.Error("解析MAC string失败")
	}
	if macAddr.String() != "11:22:33:44:55:66" {
		t.Error("MAC转string失败，应为11:22:33:44:55:66，实为", macAddr.String())
	}
	if macAddr.Int() != 18838586676582 {
		t.Error("MAC转uint64失败，应为18838586676582，实为", macAddr.Int())
	}
	macAddr = NewMACAddrFromInt(4294967295)
	if macAddr == nil {
		t.Error("解析MAC uint64失败")
	}
	if macAddr.String() != "00:00:ff:ff:ff:ff" {
		t.Error("MAC转string失败，应为00:00:ff:ff:ff:ff，实为", macAddr.String())
	}
	if macAddr.Int() != 4294967295 {
		t.Error("MAC转uint64失败，应为4294967295，实为", macAddr.Int())
	}
	if macAddr.Equals(macAddr1) {
		t.Error("Equals实现不正确 ")
	}
}

func TestEncodeAndDecode(t *testing.T) {
	ipAddr := NewIPFromString("127.0.0.1")
	buf, errno := ipAddr.GobEncode()

	if errno != nil {
		t.Error("GobEncode实现不正确 ")
	}

	ipAddr1 := &IP{}
	errno = ipAddr1.GobDecode(buf)

	if errno != nil {
		t.Error("GobDecode实现不正确 ")
	}
}
