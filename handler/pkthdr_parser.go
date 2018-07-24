package handler

import (
	"fmt"
	"net"

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
	InPort         uint32
	Exporter       net.IP
	L2End0, L2End1 bool

	PayloadLen     uint16
	PktLen         uint16
	Vlan           uint16
	EthType        layers.EthernetType
	MacSrc, MacDst net.HardwareAddr

	IpSrc, IpDst     net.IP
	Proto            layers.IPProtocol
	TTL              uint8
	PortSrc, PortDst uint16

	TcpData MetaPktTcpHdr
	TnlData MetaPktTnlHdr
	EpData  *policy.EndpointData
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
	return fmt.Sprintf("TIME: %d INPORT: 0x%X EXPORTER: %v PKT_LEN: %d IS_L2_END: %v - %v\n"+
		"    TUN_TYPE: %d TUN_ID: %d TUN_IP: %v -> %v\n"+
		"    MAC: %s -> %s TYPE: %d VLAN: %d\n"+
		"    IP: %v -> %v PROTO: %d TTL: %d\n"+
		"    PORT: %d -> %d PAYLOAD_LEN: %d FLAGS: %d SEQ: %d - %d WIN: %d WIN_SCALE: %d SACK_PREMIT: %v",
		m.Timestamp, m.InPort, m.Exporter, m.PktLen, m.L2End0, m.L2End1,
		m.TnlData.TunType, m.TnlData.TunID, m.TnlData.IpSrc, m.TnlData.IpDst,
		m.MacSrc, m.MacDst, m.EthType, m.Vlan,
		m.IpSrc, m.IpDst, m.Proto, m.TTL,
		m.PortSrc, m.PortDst, m.PayloadLen,
		m.TcpData.Flags, m.TcpData.Seq, m.TcpData.Ack, m.TcpData.WinSize, m.TcpData.WinScale, m.TcpData.SACKPermitted)
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

func (m *MetaPktHdr) Extract(rawPkt RawPacket, inPort uint32, timestamp int64, exporter net.IP) {
	packet := gopacket.NewPacket(rawPkt, layers.LayerTypeEthernet,
		gopacket.DecodeOptions{NoCopy: true, Lazy: true})
	m.InPort = inPort
	m.Timestamp = timestamp
	m.Exporter = exporter
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
}
