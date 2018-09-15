package arp

import (
	"net"
	"testing"
)

func TestArpEmptyEntry(t *testing.T) {
	_, found := Lookup(net.ParseIP("127.0.0.1"))
	if found {
		t.Error("Should be nil")
	}
}

func TestArpAnyEntry(t *testing.T) {
	table := GetTable()
	if len(table) <= 0 {
		t.Error("Shouldn't be empty")
	}
	for _, entry := range table {
		_, found := Lookup(entry.Host)
		if !found {
			t.Error("Should be found")
		}
	}
}
