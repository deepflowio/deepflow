package zerodoc

import (
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

type Metrics struct {
	TxBytes   uint32
	RxBytes   uint32
	TxPackets uint32
	RxPackets uint32
}

type MetricsField uint16

const (
	METRICS_ALL MetricsField = 1 << iota
	METRICS_EPC
	METRICS_SUBNET
	METRICS_TCP
	METRICS_EPC_TCP
	METRICS_SUBNET_TCP
	METRICS_UDP
	METRICS_EPC_UDP
	METRICS_SUBNET_UDP
	METRICS_BROADCAST
	METRICS_MULTICAST
	METRICS_UNICAST
)

type VTAPUsageMeter struct {
	Fields MetricsField

	All      Metrics
	InEPC    Metrics
	InSubnet Metrics

	TCP         Metrics
	InEPCTCP    Metrics
	InSubnetTCP Metrics

	UDP         Metrics
	InEPCUDP    Metrics
	InSubnetUDP Metrics

	Unknown   Metrics
	Broadcast Metrics
	Multicast Metrics
	Unicast   Metrics
}

func (m *Metrics) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteU32(m.TxBytes)
	encoder.WriteU32(m.RxBytes)
	encoder.WriteU32(m.TxPackets)
	encoder.WriteU32(m.RxPackets)
}

func (m *Metrics) Decode(decoder *codec.SimpleDecoder) {
	m.TxBytes = decoder.ReadU32()
	m.RxBytes = decoder.ReadU32()
	m.TxPackets = decoder.ReadU32()
	m.RxPackets = decoder.ReadU32()
}

func (m *Metrics) SortKey() uint64 {
	return uint64(m.TxBytes) + uint64(m.RxBytes)
}

func (m *Metrics) ToKVString() string {
	panic("not supported!")
}

func (m *Metrics) MarshalTo(b []byte) int {
	panic("not supported!")
}

func (m *Metrics) Clone() app.Meter {
	panic("not supported!")
}

func (m *Metrics) Release() {
	panic("not supported!")
}

func (m *Metrics) Merge(other *Metrics) {
	m.TxBytes += other.TxBytes
	m.RxBytes += other.RxBytes
	m.TxPackets += other.TxPackets
	m.RxPackets += other.RxPackets
}

func (m *Metrics) ConcurrentMerge(other app.Meter) {
	if other, ok := other.(*Metrics); ok {
		m.Merge(other)
	}
}

func (m *Metrics) SequentialMerge(other app.Meter) {
	m.ConcurrentMerge(other)
}

func (m *VTAPUsageMeter) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteU16(uint16(m.Fields))
	if m.Fields&METRICS_ALL != 0 {
		m.All.Encode(encoder)
	}
	if m.Fields&METRICS_EPC != 0 {
		m.InEPC.Encode(encoder)
	}
	if m.Fields&METRICS_SUBNET != 0 {
		m.InSubnet.Encode(encoder)
	}
	if m.Fields&METRICS_TCP != 0 {
		m.TCP.Encode(encoder)
	}
	if m.Fields&METRICS_EPC_TCP != 0 {
		m.InEPCTCP.Encode(encoder)
	}
	if m.Fields&METRICS_SUBNET_TCP != 0 {
		m.InSubnetTCP.Encode(encoder)
	}
	if m.Fields&METRICS_UDP != 0 {
		m.UDP.Encode(encoder)
	}
	if m.Fields&METRICS_EPC_UDP != 0 {
		m.InEPCUDP.Encode(encoder)
	}
	if m.Fields&METRICS_SUBNET_UDP != 0 {
		m.InSubnetUDP.Encode(encoder)
	}
	if m.Fields&METRICS_BROADCAST != 0 {
		m.Broadcast.Encode(encoder)
	}
	if m.Fields&METRICS_MULTICAST != 0 {
		m.Multicast.Encode(encoder)
	}
	if m.Fields&METRICS_UNICAST != 0 {
		m.Unicast.Encode(encoder)
	}
}

func (m *VTAPUsageMeter) Decode(decoder *codec.SimpleDecoder) {
	m.Fields = MetricsField(decoder.ReadU16())
	if m.Fields&METRICS_ALL != 0 {
		m.All.Decode(decoder)
	}
	if m.Fields&METRICS_EPC != 0 {
		m.InEPC.Decode(decoder)
	}
	if m.Fields&METRICS_SUBNET != 0 {
		m.InSubnet.Decode(decoder)
	}
	if m.Fields&METRICS_TCP != 0 {
		m.TCP.Decode(decoder)
	}
	if m.Fields&METRICS_EPC_TCP != 0 {
		m.InEPCTCP.Decode(decoder)
	}
	if m.Fields&METRICS_SUBNET_TCP != 0 {
		m.InSubnetTCP.Decode(decoder)
	}
	if m.Fields&METRICS_UDP != 0 {
		m.UDP.Decode(decoder)
	}
	if m.Fields&METRICS_EPC_UDP != 0 {
		m.InEPCUDP.Decode(decoder)
	}
	if m.Fields&METRICS_SUBNET_UDP != 0 {
		m.InSubnetUDP.Decode(decoder)
	}
	if m.Fields&METRICS_BROADCAST != 0 {
		m.Broadcast.Decode(decoder)
	}
	if m.Fields&METRICS_MULTICAST != 0 {
		m.Multicast.Decode(decoder)
	}
	if m.Fields&METRICS_UNICAST != 0 {
		m.Unicast.Decode(decoder)
	}
}

func (m *VTAPUsageMeter) SortKey() uint64 {
	return m.All.SortKey()
}

func (m *VTAPUsageMeter) ToKVString() string {
	panic("not supported!")
}

func (m *VTAPUsageMeter) MarshalTo(b []byte) int {
	panic("not supported!")
}

func (m *VTAPUsageMeter) ConcurrentMerge(other app.Meter) {
	if other, ok := other.(*VTAPUsageMeter); ok {
		m.Fields |= other.Fields

		if m.Fields&METRICS_ALL != 0 {
			m.All.Merge(&other.All)
		}
		if m.Fields&METRICS_EPC != 0 {
			m.InEPC.Merge(&other.InEPC)
		}
		if m.Fields&METRICS_SUBNET != 0 {
			m.InSubnet.Merge(&other.InSubnet)
		}

		if m.Fields&METRICS_TCP != 0 {
			m.TCP.Merge(&other.TCP)
		}
		if m.Fields&METRICS_EPC_TCP != 0 {
			m.InEPCTCP.Merge(&other.InEPCTCP)
		}
		if m.Fields&METRICS_SUBNET_TCP != 0 {
			m.InSubnetTCP.Merge(&other.InSubnetTCP)
		}

		if m.Fields&METRICS_UDP != 0 {
			m.UDP.Merge(&other.UDP)
		}
		if m.Fields&METRICS_EPC_UDP != 0 {
			m.InEPCUDP.Merge(&other.InEPCUDP)
		}
		if m.Fields&METRICS_SUBNET_UDP != 0 {
			m.InSubnetUDP.Merge(&other.InSubnetUDP)
		}
		if m.Fields&METRICS_BROADCAST != 0 {
			m.Broadcast.Merge(&other.Broadcast)
		}
		if m.Fields&METRICS_MULTICAST != 0 {
			m.Multicast.Merge(&other.Multicast)
		}
		if m.Fields&METRICS_UNICAST != 0 {
			m.Unicast.Merge(&other.Unicast)
		}
	}
}

func (m *VTAPUsageMeter) SequentialMerge(other app.Meter) {
	m.ConcurrentMerge(other)
}
