package datatype

import (
	"fmt"

	. "github.com/google/gopacket/layers"
)

type TapType uint8

const (
	TAP_ANY TapType = iota
	TAP_ISP
	TAP_SPINE
	TAP_TOR
	TAP_MAX
)

type EndpointInfo struct {
	L2EpcId      int32 // -1表示其它项目
	L2DeviceType uint32
	L2DeviceId   uint32
	L2End        bool

	L3EpcId      int32 // -1表示其它项目
	L3DeviceType uint32
	L3DeviceId   uint32
	L3End        bool

	HostIp   uint32
	SubnetId uint32
	GroupIds []uint32
}

type LookupKey struct {
	SrcMac, DstMac   uint64
	SrcIp, DstIp     uint32
	SrcPort, DstPort uint16
	EthType          EthernetType
	Vlan             uint16
	Proto            uint8
	Ttl              uint8
	RxInterface      uint32
	L2End0, L2End1   bool
	Tap              TapType
	Invalid          bool
	FastIndex        int
}

type EndpointData struct {
	SrcInfo *EndpointInfo
	DstInfo *EndpointInfo
}

func NewEndpointData() *EndpointData {
	return &EndpointData{
		SrcInfo: &EndpointInfo{},
		DstInfo: &EndpointInfo{},
	}
}

func (i *EndpointInfo) SetL2Data(data *PlatformData) {
	i.L2EpcId = data.EpcId
	i.L2DeviceType = data.DeviceType
	i.L2DeviceId = data.DeviceId
	i.HostIp = data.HostIp
	i.GroupIds = append(i.GroupIds, data.GroupIds...)
}

func (i *EndpointInfo) SetL3Data(data *PlatformData, ip uint32) {
	i.L3EpcId = -1
	if data.EpcId != 0 {
		i.L3EpcId = data.EpcId
	}
	i.L3DeviceType = data.DeviceType
	i.L3DeviceId = data.DeviceId

	for _, ipInfo := range data.Ips {
		if ipInfo.Ip == (ip & (NETMASK << (MAX_MASK_LEN - ipInfo.Netmask))) {
			i.SubnetId = ipInfo.SubnetId
			break
		}
	}
}

func (i *EndpointInfo) SetL3EndByTtl(ttl uint8) {
	if ttl == 64 || ttl == 128 || ttl == 255 {
		i.L3End = true
	}
}

func (i *EndpointInfo) SetL3EndByIp(data *PlatformData, ip uint32) {
	for _, ipInfo := range data.Ips {
		if ipInfo.Ip == (ip & (NETMASK << (MAX_MASK_LEN - ipInfo.Netmask))) {
			i.L3End = true
			break
		}
	}
}

func (i *EndpointInfo) SetL3EndByMac(data *PlatformData, mac uint64) {
	if data.Mac == mac {
		i.L3End = true
	}
}

func (d *EndpointData) SetL2End(key *LookupKey) {
	d.SrcInfo.L2End = key.L2End0
	d.DstInfo.L2End = key.L2End1
}

func (d *EndpointData) String() string {
	return fmt.Sprintf("SRC: %+v,DST: %+v", *d.SrcInfo, *d.DstInfo)
}

func (t *TapType) CheckTapType(tapType TapType) bool {
	if tapType < TAP_MAX {
		return true
	}
	return false
}
