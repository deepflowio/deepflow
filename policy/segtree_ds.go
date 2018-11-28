package policy

import (
	"encoding/binary"
	"net"

	tree "gitlab.x.lan/yunshan/droplet-libs/segmenttree"
)

type IpRange struct {
	net.IPNet

	lower uint32
	upper uint32
}

func newIpRange(ip uint32) *IpRange {
	return &IpRange{lower: ip, upper: ip}
}

func newIpRangeFromString(ipStr string) (*IpRange, error) {
	_, r, err := net.ParseCIDR(ipStr)
	if err != nil {
		log.Warning(err)
		return nil, err
	}
	ipInt := binary.BigEndian.Uint32(r.IP)
	maskInt := binary.BigEndian.Uint32(r.Mask)
	return &IpRange{*r, ipInt & maskInt, ipInt | ^maskInt}, nil
}

func (r *IpRange) Lower() (endpoint tree.Endpoint, closed bool) {
	return int64(r.lower), true
}

func (r *IpRange) Upper() (endpoint tree.Endpoint, closed bool) {
	return int64(r.upper), true
}

type epcRange struct {
	lower int32
	upper int32
}

func newEpcRange(id int32) *epcRange {
	if id <= 0 {
		return &epcRange{1, 0x7FFFFFFF}
	}
	return &epcRange{id, id}
}

func queryEpcRange(id int32) *epcRange {
	if id <= 0 {
		return &epcRange{0x7FFFFFFF, 0x7FFFFFFF}
	}
	return &epcRange{id, id}
}

func (r *epcRange) Lower() (endpoint tree.Endpoint, closed bool) {
	return int64(r.lower), true
}

func (r *epcRange) Upper() (endpoint tree.Endpoint, closed bool) {
	return int64(r.upper), true
}

type leafValue int32

// Id implements Value interface
func (v leafValue) Id() uint64 {
	return uint64(v)
}
