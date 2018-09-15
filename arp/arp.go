package arp

import (
	"net"
	"time"

	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

type IPv4Int = uint32

type ArpEntry struct {
	Host      net.IP
	HwAddr    net.HardwareAddr
	Interface *net.Interface
}

type ArpTable = map[IPv4Int]ArpEntry

var (
	table = make(ArpTable)
)

func Lookup(host net.IP) (ArpEntry, bool) {
	entry, found := table[IpToUint32(host.To4())]
	return entry, found
}

func init() {
	table = GetTable()
	go func() {
		for range time.NewTicker(30 * time.Second).C {
			table = GetTable()
		}
	}()
}
