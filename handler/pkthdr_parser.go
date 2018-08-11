package handler

import (
	"fmt"
	"net"
	"reflect"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"gitlab.x.lan/yunshan/droplet-libs/policy"
	. "gitlab.x.lan/yunshan/droplet/utils"
)

type RawPacket []byte

type MetaPktTnlHdr struct {
	TunType      uint8
	TunID        uint32
	IpSrc, IpDst net.IP
}

type MetaPktTcpHdr struct {
	Flags         uint8
	Seq           uint32
	Ack           uint32
	WinSize       uint16
	WinScale      uint8
	SACKPermitted bool
}

const (
	CAPTURE_LOCAL  = 0x10000
	CAPTURE_REMOTE = 0x30000
)

type MetaPktHdr struct {
	Timestamp      int64
	InPort         uint32 `fmt:"hex"`
	PktLen         uint16
	Exporter       net.IP
	L2End0, L2End1 bool
	EpData         *policy.EndpointData `fmt:"pointer"`
	Raw            RawPacket            `fmt:"pointer+enter"`

	TnlData MetaPktTnlHdr `fmt:"tab+v+enter"`

	MacSrc  net.HardwareAddr `fmt:"tab"`
	MacDst  net.HardwareAddr
	EthType layers.EthernetType
	Vlan    uint16 `fmt:"enter"`

	IpSrc net.IP `fmt:"tab"`
	IpDst net.IP
	Proto layers.IPProtocol
	TTL   uint8 `fmt:"enter"`

	PortSrc    uint16 `fmt:"tab"`
	PortDst    uint16
	PayloadLen uint16
	TcpData    MetaPktTcpHdr `fmt:"+v"`
}

func get_tcp_flags(t *layers.TCP) uint8 {
	f := uint8(0)
	if t.FIN {
		f |= 0x01
	}
	if t.SYN {
		f |= 0x02
	}
	if t.RST {
		f |= 0x04
	}
	if t.PSH {
		f |= 0x08
	}
	if t.ACK {
		f |= 0x10
	}
	if t.URG {
		f |= 0x20
	}
	if t.ECE {
		f |= 0x40
	}
	if t.CWR {
		f |= 0x80
	}
	return f
}

func (m *MetaPktHdr) String() string {
	s := reflect.ValueOf(m).Elem()
	t := s.Type()
	out := ""

	for i := 0; i < s.NumField(); i++ {
		f := s.Field(i)
		name := t.Field(i).Tag.Get("fmt")
		switch name {
		case "tab+v+enter":
			out += fmt.Sprintf("    %s: %+v\n", t.Field(i).Name, f.Interface())
			break
		case "pointer+enter":
			out += fmt.Sprintf("%s: %p\n", t.Field(i).Name, f.Interface())
			break
		case "pointer":
			out += fmt.Sprintf("%s: %p ", t.Field(i).Name, f.Interface())
			break
		case "":
			out += fmt.Sprintf("%s: %v ", t.Field(i).Name, f.Interface())
			break
		case "tab":
			out += fmt.Sprintf("    %s: %v ", t.Field(i).Name, f.Interface())
			break
		case "enter":
			out += fmt.Sprintf("%s: %v\n", t.Field(i).Name, f.Interface())
			break
		case "+v":
			out += fmt.Sprintf("%s: %+v", t.Field(i).Name, f.Interface())
			break
		case "enter++v":
			out += fmt.Sprintf("%s: %+v\n", t.Field(i).Name, f.Interface())
			break
		case "hex":
			out += fmt.Sprintf("%s: 0x%X ", t.Field(i).Name, f.Interface())
			break
		}
	}
	return out
}

func (m *MetaPktHdr) extractTcpOptions(rawPkt RawPacket, offset uint16, max uint16) {
	for offset+1 < max { // 如果不足2B，EOL和NOP都可以忽略
		assumeLength := uint16(Max(int(rawPkt[offset+1]), 2))
		switch rawPkt[offset] {
		case layers.TCPOptionKindEndList:
			return
		case layers.TCPOptionKindNop:
			offset++
		case layers.TCPOptionKindWindowScale:
			if offset+assumeLength > max {
				return
			}
			m.TcpData.WinScale = byte(rawPkt[offset+2])
			offset += assumeLength
		case layers.TCPOptionKindSACKPermitted:
			m.TcpData.SACKPermitted = true
			offset += 2
		default: // others
			offset += assumeLength
		}
	}
}

func NewMetaPktHdr(rawPkt RawPacket, inPort uint32, timestamp int64, exporter net.IP) *MetaPktHdr {
	m := &MetaPktHdr{InPort: inPort, Exporter: exporter, Timestamp: timestamp, Raw: rawPkt}
	packet := gopacket.NewPacket(rawPkt, layers.LayerTypeEthernet,
		gopacket.DecodeOptions{NoCopy: true, Lazy: true})
	eth := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	m.MacDst = eth.DstMAC
	m.MacSrc = eth.SrcMAC
	m.EthType = eth.EthernetType
	if m.EthType == layers.EthernetTypeDot1Q {
		vlan := packet.Layer(layers.LayerTypeDot1Q).(*layers.Dot1Q)
		m.EthType = vlan.Type
		m.Vlan = vlan.VLANIdentifier
	}

	if m.EthType == layers.EthernetTypeIPv4 {
		ip := packet.NetworkLayer().(*layers.IPv4)
		m.IpSrc = ip.SrcIP
		m.IpDst = ip.DstIP
		m.TTL = ip.TTL
		m.Proto = ip.Protocol
		if m.Vlan > 0 {
			m.PktLen = 4
		}
		m.PktLen += ip.Length + 14
		if m.Proto == layers.IPProtocolTCP {
			tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
			m.PortSrc = uint16(tcp.SrcPort)
			m.PortDst = uint16(tcp.DstPort)
			m.PayloadLen = ip.Length - uint16(tcp.DataOffset*4)
			m.TcpData.Flags = get_tcp_flags(tcp)
			m.TcpData.Seq = tcp.Seq
			m.TcpData.Ack = tcp.Ack
			m.TcpData.WinSize = tcp.Window
			m.extractTcpOptions(rawPkt, m.PktLen-m.PayloadLen, m.PayloadLen)
		} else if m.Proto == layers.IPProtocolUDP {
			udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
			m.PortSrc = uint16(udp.SrcPort)
			m.PortDst = uint16(udp.DstPort)
			m.PayloadLen = udp.Length - 8
		}
	}
	return m
}
