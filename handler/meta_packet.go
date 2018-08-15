package handler

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"gitlab.x.lan/yunshan/droplet-libs/policy"
	. "gitlab.x.lan/yunshan/droplet/utils"
)

type RawPacket = []byte

type IPv4Int = uint32

type MetaPacketTcpHeader struct {
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

type MetaPacket struct {
	TunnelInfo

	Timestamp      time.Duration
	InPort         uint32
	PacketLen      uint16
	Exporter       net.IP
	L2End0, L2End1 bool
	EndpointData   *policy.EndpointData
	Raw            RawPacket

	MacSrc  net.HardwareAddr
	MacDst  net.HardwareAddr
	EthType layers.EthernetType
	Vlan    uint16

	IpSrc, IpDst IPv4Int
	Proto        layers.IPProtocol
	TTL          uint8

	PortSrc    uint16
	PortDst    uint16
	PayloadLen uint16
	TcpData    MetaPacketTcpHeader
}

func (m *MetaPacket) String() string {
	return fmt.Sprintf("TIMESTAMP: %d INPORT: 0x%X EXPORTER: %v PKT_LEN: %d IS_L2_END: %v - %v ENDPOINTDATA: %p RAW: %p\n"+
		"    TUNNEL: %+v\n"+
		"    MAC: %s -> %s TYPE: %d VLAN: %d\n"+
		"    IP: %v -> %v PROTO: %d TTL: %d\n"+
		"    PORT: %d -> %d PAYLOAD_LEN: %d TCP: %+v",
		m.Timestamp, m.InPort, m.Exporter, m.PacketLen, m.L2End0, m.L2End1, m.EndpointData, m.Raw,
		m.TunnelInfo,
		m.MacSrc, m.MacDst, m.EthType, m.Vlan,
		m.IpSrc, m.IpDst, m.Proto, m.TTL,
		m.PortSrc, m.PortDst, m.PayloadLen, m.TcpData)
}

func getTcpFlags(t *layers.TCP) uint8 {
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

func (m *MetaPacket) extractTcpOptions(rawPacket RawPacket, offset uint16, max uint16) {
	for offset+1 < max { // 如果不足2B，EOL和NOP都可以忽略
		assumeLength := uint16(Max(int(rawPacket[offset+1]), 2))
		switch rawPacket[offset] {
		case layers.TCPOptionKindEndList:
			return
		case layers.TCPOptionKindNop:
			offset++
		case layers.TCPOptionKindWindowScale:
			if offset+assumeLength > max {
				return
			}
			m.TcpData.WinScale = byte(rawPacket[offset+2])
			offset += assumeLength
		case layers.TCPOptionKindSACKPermitted:
			m.TcpData.SACKPermitted = true
			offset += 2
		default: // others
			offset += assumeLength
		}
	}
}

func NewMetaPacket(rawPacket RawPacket, inPort uint32, timestamp time.Duration, exporter net.IP) *MetaPacket {
	m := &MetaPacket{InPort: inPort, Exporter: exporter, Timestamp: timestamp, Raw: rawPacket}
	packet := gopacket.NewPacket(rawPacket, layers.LayerTypeEthernet,
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

	if m.EthType != layers.EthernetTypeIPv4 {
		return m
	}

	ip := packet.NetworkLayer().(*layers.IPv4)
	m.IpSrc = IpToUint32(ip.SrcIP)
	m.IpDst = IpToUint32(ip.DstIP)
	m.TTL = ip.TTL
	m.Proto = ip.Protocol
	if m.Vlan > 0 {
		m.PacketLen = 4
	}
	m.PacketLen += ip.Length + 14
	if m.Proto == layers.IPProtocolTCP {
		tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		m.PortSrc = uint16(tcp.SrcPort)
		m.PortDst = uint16(tcp.DstPort)
		m.PayloadLen = ip.Length - uint16(tcp.DataOffset*4)
		m.TcpData.Flags = getTcpFlags(tcp)
		m.TcpData.Seq = tcp.Seq
		m.TcpData.Ack = tcp.Ack
		m.TcpData.WinSize = tcp.Window
		m.extractTcpOptions(rawPacket, m.PacketLen-m.PayloadLen, m.PayloadLen)
	} else if m.Proto == layers.IPProtocolUDP {
		udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		m.PortSrc = uint16(udp.SrcPort)
		m.PortDst = uint16(udp.DstPort)
		m.PayloadLen = udp.Length - 8
	}
	return m
}
