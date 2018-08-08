package datatype

import "testing"

func TestIP(t *testing.T) {
	ipAddr := NewIPFromString("127.0.0.1")
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
}

func TestMAC(t *testing.T) {
	macAddr := NewMACAddrFromString("11:22:33:44:55:66")
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
}
